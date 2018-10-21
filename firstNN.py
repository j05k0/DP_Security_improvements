import tensorflow as tf
from numba.typing import typeof
from tensorflow import keras

import numpy as np
import matplotlib.pyplot as plt

types = ['i4', 'f8', 'U20', 'U10', 'U3', 'i4', 'i4', 'i4', 'i4', 'f8',
         'i4', 'i4', 'f8', 'f8', 'i4', 'i4', 'f8', 'f8', 'f8', 'f8',
         'i4', 'i4', 'i4', 'i4', 'f8', 'f8', 'f8', 'i4', 'i4', 'i4',
         'i4', 'i4', 'i4', 'i4', 'i4', 'i4', 'i4', 'i4', 'i4', 'i4',
         'i4', 'i4', 'i4', 'U20', 'i4']
#train = np.genfromtxt('datasets/UNSW_NB15_train_small.csv',dtype=types, delimiter=',', names=True)
train = np.genfromtxt('datasets/UNSW_NB15_training-set.csv', dtype=types, delimiter=',', names=True)
trainLabels = train['label']
print len(trainLabels)
print 'Training set: ', train.shape

#TODO how to deal with categorical data
