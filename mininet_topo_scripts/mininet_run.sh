# Script for running Mininet with custom topology
# Place this script in the same folder as topo's source

sudo mn --topo dptopo --custom topo1.py --controller=remote --switch ovsk,protocols=OpenFlow13

