import matplotlib.pyplot as plt
import numpy as np
import sys

path = sys.argv[1]

y = np.loadtxt(path, delimiter=',', dtype=float, skiprows=1)

fig, ax = plt.subplots()
for i in range(10):
    ax.plot(y[16*i:16*(i + 1),0], y[16*i:16*(i + 1),2])

plt.xlabel("Size of input")
plt.ylabel("Time elapsed (ms)")
plt.show()

