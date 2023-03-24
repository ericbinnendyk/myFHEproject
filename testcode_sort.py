import matplotlib.pyplot as plt
import numpy as np
import sys

path = sys.argv[1]

y = np.loadtxt(path, delimiter=',', dtype=float, skiprows=1)

fig, ax = plt.subplots()
for i in range(3):
    ax.plot(y[9*i:9*(i + 1),1], y[9*i:9*(i + 1),3])

plt.xlabel("Array length")
plt.ylabel("Time elapsed (ms)")
plt.show()

