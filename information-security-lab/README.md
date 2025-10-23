# information-security-lab

MAT PLOT LIB 

Creating a Basic Plot
plt.plot(x, y)              # Plot y versus x as lines and/or markers
plt.scatter(x, y)           # Scatter plot (points only)
plt.bar(x, height)          # Bar chart
plt.hist(data, bins=n)      # Histogram
plt.pie(sizes)              # Pie chart
Display and Save Plot
plt.show()                  # Display the plot window
plt.savefig('filename.png') # Save the current figure to a file
Customizing Plot Appearance
plt.plot(x, y, color='red')         # Change line color
plt.plot(x, y, linestyle='--')      # Change line style (e.g., dashed)
plt.plot(x, y, marker='o')           # Add markers to points
plt.xlim(xmin, xmax)                # Set limits for x-axis
plt.ylim(ymin, ymax)                # Set limits for y-axis
plt.grid(True)                     # Show grid
Subplots
fig, axs = plt.subplots(nrows=2, ncols=2)  # Create 2x2 grid of subplots
axs[0, 0].plot(x, y)                       # Plot on first subplot
plt.tight_layout()                         # Adjust subplot layout to fit
Other Useful Commands
plt.clf()          # Clear the current figure
plt.cla()          # Clear the current axes
plt.close()        # Close a figure window

