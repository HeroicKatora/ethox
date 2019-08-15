#!/usr/bin/python2
import difflib

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class HostToEthoxTopo(Topo):
    "Single switch connected to n hosts."
    def build(self):
        host = self.addHost('host')
        ethox = self.addHost('ethox')
        self.addLink(host, ethox, intfName2='ethoxtap')

def simpleTest():
    "Create and test a simple network"
    topo = HostToEthoxTopo()
    net = Mininet(topo, controller = OVSController)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()

    host = net.get('host')
    host.cmd('python3 -m http.server --bind %s 8000 &' % (host.IP()))
    host.cmd('sleep 1')

    ethox = net.get('ethox')
    expected = ethox.cmd('curl %s:8000' % (host.IP()))

    # Remove the ip addr to disable host ip+tcp response. Can't bring the whole link down.
    # Then wait for a short time to allow the server to boot and other effects to take place.
    ethox.cmd('ip addr flush dev ethoxtap')

    # There are some weird ' > > > >' in the answer if this is not on the same
    # shell line.  I wish mininet had better job control and output retrieval,
    # like real python instead of a direct **terminal** fd0/fd1 interaction.
    # FIXME: subnet specifiers should not be hardcoded
    ethox_tcp = '../target/debug/examples/curl ethoxtap %s/8 %s %s/8 %s %s %s' % (
        ethox.IP(), ethox.MAC(), host.IP(), host.MAC(), host.IP(), 8000)
    # The connection lingers in tcp TimeWait for 6 more seconds (2 full default rtts)
    answer = ethox.cmd('timeout 8s ' + ethox_tcp)
    print answer
    print '\n'.join(filter(
        lambda l: not l.startswith('  '),
        difflib.ndiff(expected, answer)))
    assert expected == answer

    host.cmd('kill %python3')
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
