# remove_bg.py

from rembg import remove
from PIL import Image

# Input and output paths
input_path = "lapy.jpg"   # Replace with your image file
output_path = "output_image.png" # Output file with background removed

# Open the image
input_image = Image.open(input_path)

# Remove the background
output_image = remove(input_image)

# Save the result
output_image.save(output_path)

print(f"Background removed! Saved as {output_path}")
