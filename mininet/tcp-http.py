#!/usr/bin/python2

from mininet.topo import Topo
from mininet.net import Mininet
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
    net = Mininet(topo)
    net.start()
    print "Dumping host connections"
    dumpNodeConnections(net.hosts)
    print "Testing network connectivity"
    net.pingAll()

    host = net.get('host')
    host.cmd('python3 -m http.server --bind %s 8000 &' % (host.IP()))
    # host.cmd('wireshark &')
    # host.cmd('xterm') # as a pause mechanism

    ethox = net.get('ethox')
    expected = ethox.cmd('curl %s:8000' % (host.IP()))

    simple_get = '"GET / HTTP/1.0\r\n\r\n"'
    # FIXME: subnet specifiers should not be hardcoded
    ethox_tcp = './target/debug/examples/tcp_hello ethoxtap %s/8 %s %s/8 %s %s %s %s' % (
        ethox.IP(), ethox.MAC(), host.IP(), host.MAC(), host.IP(), 8000, simple_get)
    print ethox.cmd('cd .. && ' + ethox_tcp)

    host.cmd('kill %python3')
    net.stop()

if __name__ == '__main__':
    # Tell mininet to print useful information
    setLogLevel('info')
    simpleTest()
