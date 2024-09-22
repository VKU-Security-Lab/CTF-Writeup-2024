import numpy as np
import matplotlib.pyplot as plt

samples = np.fromfile('play_it_on_the_radio.iq', np.complex64) # Read in file.  We have to tell it what format it is
print(samples)

# Plot constellation to make sure it looks right
plt.plot(np.real(samples), np.imag(samples), '.')
plt.grid(True)
plt.show()