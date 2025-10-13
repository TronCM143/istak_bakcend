import os
from typing import List, Dict, Optional

import pandas as pd
from prophet import Prophet

# Optional: only needed when you want to aggregate from Django DB
try:
    from django.db.models import Count
    from django.db.models.functions import TruncMonth
    from django.utils import timezone
except Exception:  # pragma: no cover
    timezone = None  # allows this module to be imported outside Django

from dateutil.relativedelta import relativedelta

# ----------------------------
# Cleaning / Aggregation
# ----------------------------

def _standardize_raw_df(df: pd.DataFrame) -> pd.DataFrame:
    """Minimal cleaning for the raw transactions dataset.
    Expects columns: ['item', 'borrow_date']
    """
    work = df.copy()
    work = work[["item", "borrow_date"]].dropna(subset=["item", "borrow_date"]).copy()
    work["borrow_date"] = pd.to_datetime(work["borrow_date"], errors="coerce")
    work = work.dropna(subset=["borrow_date"])  # drop rows where parsing failed
    # Normalize item names to avoid duplicates due to casing/spacing
    work["item"] = work["item"].astype(str).str.strip().str.lower()
    work = work.drop_duplicates()
    return work


def build_monthly_counts_from_df(src: pd.DataFrame) -> pd.DataFrame:
    """From a cleaned DataFrame, build monthly totals per item.
    Returns: DataFrame with columns ['borrow_date','item','count'] where borrow_date is month-end.
    """
    work = _standardize_raw_df(src)
    monthly = (
        work.groupby([pd.Grouper(key="borrow_date", freq="M"), "item"]).size().reset_index(name="count")
    )
    # align to month-end to match Prophet freq='M'
    monthly["borrow_date"] = monthly["borrow_date"].dt.to_period("M").dt.to_timestamp(how="end")
    return monthly.sort_values(["item", "borrow_date"]).reset_index(drop=True)


# ----------------------------
# Loading from Excel (file path or Google Sheets xlsx export URL)
# ----------------------------

def build_monthly_counts_from_excel(source: str) -> pd.DataFrame:
    """Load an Excel dataset (local path or Google Sheets xlsx export URL)
    and return monthly counts per item.
    """
    df = pd.read_excel(source, engine="openpyxl")
    return build_monthly_counts_from_df(df)


# ----------------------------
# Loading from Django DB (Transaction model)
# ----------------------------
try:
    from .models import Transaction  # type: ignore
except Exception:  # pragma: no cover
    Transaction = None


def build_monthly_counts_from_db(user) -> pd.DataFrame:
    """Return monthly borrow counts per item for this user/manager context.
    Requires Django and a Transaction model.
    """
    if Transaction is None:
        raise RuntimeError("Transaction model is not available; are you running inside Django?")

    # Scope by role
    if getattr(user, "role", None) == "user_web":
        base = Transaction.objects.filter(manager=user)
    elif getattr(user, "role", None) == "user_mobile" and getattr(user, "manager", None):
        base = Transaction.objects.filter(manager=user.manager)
    else:
        return pd.DataFrame(columns=["borrow_date", "item", "count"])  # empty

    qs = (
        base.values("items__item_name", month=TruncMonth("borrow_date")).annotate(count=Count("items"))
    )
    df = pd.DataFrame(list(qs))
    if df.empty:
        return df

    df = df.rename(columns={"month": "borrow_date", "items__item_name": "item"})
    df["borrow_date"] = pd.to_datetime(df["borrow_date"])  # month start
    df["borrow_date"] = df["borrow_date"].dt.to_period("M").dt.to_timestamp(how="end")

    # Normalize item names same as Excel path
    df["item"] = df["item"].astype(str).str.strip().str.lower()

    return df[["borrow_date", "item", "count"]].sort_values(["item", "borrow_date"]).reset_index(drop=True)


# ----------------------------
# Forecasting helpers
# ----------------------------

def _months_between(a: pd.Timestamp, b: pd.Timestamp) -> int:
    """Whole months from b -> a (can be negative)."""
    return (a.year - b.year) * 12 + (a.month - b.month)


def predict_top_items_for_month(
    monthly_counts: pd.DataFrame,
    target_month: Optional[str] = None,
    top_k: int = 5,
    min_points_per_item: int = 3,
) -> List[Dict]:
    """Use Prophet (per item) to predict top borrowed items for the requested month.

    Args:
        monthly_counts: DataFrame with ['borrow_date','item','count'] at monthly freq.
        target_month: 'YYYY-MM'. If None, defaults to next calendar month from today (server time if Django's timezone is available).
        top_k: number of items to return.
        min_points_per_item: minimum history points per item required to build a model.

    Returns: list of dicts [{'rank':1,'item':'..','predicted':float,'month':'YYYY-MM'}, ...]
    """
    if monthly_counts is None or monthly_counts.empty:
        return []

    mc = monthly_counts.copy()
    mc["borrow_date"] = pd.to_datetime(mc["borrow_date"])
    mc["borrow_date"] = mc["borrow_date"].dt.to_period("M").dt.to_timestamp(how="end")

    # Default to next month
    if target_month is None:
        if timezone is not None:
            next_month = (timezone.localdate() + relativedelta(months=1)).strftime("%Y-%m")
        else:
            next_month = (pd.Timestamp.today().to_pydatetime().date() + relativedelta(months=1)).strftime("%Y-%m")
        target_month = next_month

    target_period = pd.Period(target_month, freq="M")
    target_ts = target_period.to_timestamp(how="end")

    rows: List[Dict] = []

    for item, grp in mc.groupby("item"):
        grp = grp.sort_values("borrow_date")
        if len(grp) < min_points_per_item:
            continue

        df_prophet = grp.rename(columns={"borrow_date": "ds", "count": "y"})

        m = Prophet(yearly_seasonality=True, weekly_seasonality=False, daily_seasonality=False)
        m.fit(df_prophet)

        last_obs = df_prophet["ds"].max()
        horizon_months = max(_months_between(target_ts, last_obs), 0)

        future = m.make_future_dataframe(periods=horizon_months + 2, freq="M")  # +buffer
        fcst = m.predict(future)
        fcst["period"] = fcst["ds"].dt.to_period("M")
        row = fcst.loc[fcst["period"] == target_period]
        if not row.empty:
            rows.append({"item": str(item), "predicted": float(row["yhat"].iloc[0])})

    rows.sort(key=lambda r: r["predicted"], reverse=True)
    for i, r in enumerate(rows, start=1):
        r["rank"] = i
        r["month"] = target_month

    return rows[: top_k]


# ----------------------------
# Convenience wrappers
# ----------------------------

def forecast_next_month_from_excel(source: str, top_k: int = 5, min_points_per_item: int = 3) -> List[Dict]:
    """One-call helper: load Excel -> monthly counts -> predict next month top items."""
    monthly_counts = build_monthly_counts_from_excel(source)
    return predict_top_items_for_month(
        monthly_counts=monthly_counts,
        target_month=None,  # next month by default
        top_k=top_k,
        min_points_per_item=min_points_per_item,
    )


def forecast_next_month_from_db(user, top_k: int = 5, min_points_per_item: int = 3) -> List[Dict]:
    """One-call helper: load from DB -> monthly counts -> predict next month top items."""
    monthly_counts = build_monthly_counts_from_db(user)
    return predict_top_items_for_month(
        monthly_counts=monthly_counts,
        target_month=None,
        top_k=top_k,
        min_points_per_item=min_points_per_item,
    )
