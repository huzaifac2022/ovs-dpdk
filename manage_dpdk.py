#!/usr/bin/env python
#
# Copyright(c) 2022 Nutanix Inc. All rights reserved.
#
# Author: karthik.c@nutanix.com

import argparse
import collections
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as et

BridgeConfig = collections.namedtuple(
  "BridgeConfig", ("name", "ip", "network", "gateway"))
devbind_script = "/root/dpdk/dpdk-devbind.py"

def usage(err=None):
  if err:
    sys.stdout.write("Error: %s\n" % err)
  if err:
    sys.exit(1)

def run_cmd(cmd):
  sys.stdout.write("Executing: %s\n" % cmd)
  proc = subprocess.Popen(cmd, shell=True,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE)
  out, err = proc.communicate()
  if err:
    sys.stdout.write("Command execution failed with: %s\n" % err)
    sys.exit(1)
  return out

def validate_ipv4_address(ip):
  try:
    ipaddress.IPv4Address(unicode(ip))
  except Exception:
    usage(err="Invalid IP %s" % ip)

def validate_ipv4_network(network):
  try:
    ipaddress.IPv4Network(unicode(network))
  except Exception:
    usage(err="Invalid Network: %s" % network)

def validate_bridge_tag(bridge_tag):
  if bridge_tag < 0 or bridge_tag > 4095:
    usage(err="Invalid VLAN tag: %d" % bridge_tag)

def list_bridges():
  result = run_cmd("ovs-vsctl list-br")
  return result.splitlines()

def list_ports(bridge):
  result = run_cmd("ovs-vsctl list-ports %s" % bridge)
  return result.splitlines()

def get_interface_pci_address(interface):
  result = run_cmd("ovs-vsctl --id=@%s get interface %s options:dpdk-devargs" %
                   (interface, interface))
  return result.rstrip('\n').strip('"')

def list_kernel_devices():
  devices = {}
  out = run_cmd("python %s --status-dev net" % devbind_script)
  for line in out.split('\n'):
    device_info = re.match(
      r'(^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]{1})', line)
    if device_info:
      pci_address = device_info.groups()[0]
      interface = None
      m = re.search(r'if=([\S]+)', line)
      if m:
        interface = m.groups()[0]
      driver = None
      m = re.search(r'drv=([\S]+)', line)
      if m:
        driver = m.groups()[0]
      unused = None
      m = re.search(r'unused=([\S]+)', line)
      if m:
        unused = m.groups()[0]
      if interface:
        devices[interface] = {
          "pci_address": pci_address,
          "driver": driver,
          "unused": unused.split(',') if unused else []
        }

  return devices

def list_dpdk_devices():
  devices = {}
  out = run_cmd("python %s --status-dev net" % devbind_script)
  for line in out.split('\n'):
    device_info = re.match(
      r'(^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]{1})', line)
    if device_info:
      pci_address = device_info.groups()[0]
      driver = None
      m = re.search(r'drv=([\S]+)', line)
      if m:
        driver = m.groups()[0]
      unused = None
      m = re.search(r'unused=([\S]+)', line)
      if m:
        unused = m.groups()[0]
      devices[pci_address] = {
        "driver": driver,
        "unused": unused.split(',') if unused else []
      }

  return devices

def get_intf_dpdk_command(interface, pci_address):
  return " -- set Interface %s type=dpdk options:dpdk-devargs=%s" % (interface,
                                                                     pci_address)

def get_bond(bridge):
  return bridge + "-up"

def get_uplink_bridge(bridge):
  return bridge + ".out"

def get_uplink_port(bridge):
  uplink_bridge = get_uplink_bridge(bridge)
  return uplink_bridge + ".u"

def get_uplink_peer_port(bridge):
  return bridge + ".d"

def get_arp_dhcp_port(bridge):
  return bridge + "-arp-dhcp"

def bind_interfaces_to_dpdk(interfaces):
  # Get information about all devices bound to Kernel.
  devices = list_kernel_devices()

  # Validate that all the interfaces exist in the Kernel.
  for interface in interfaces:
    if (interface not in devices or
        "vfio-pci" not in devices[interface].get("unused")):
      usage(err="Invalid interface: %s" % interface)

  # Bind all interfaces to vfio-pci
  for interface in interfaces:
    _ = run_cmd("python %s --bind=vfio-pci %s" % (devbind_script, interface))

  return {intf: devices[intf] for intf in devices if intf in interfaces}

def bind_interfaces_to_kernel(pci_addresses):
  # Get information of all devices bound to vfio-pci.
  devices = list_dpdk_devices()

  # Validate the pci_address.
  for pci_address in pci_addresses:
    if pci_address not in devices:
      usage(err="Invalid pci_address: %s" % pci_address)

  # Bind interfaces back to Kernel.
  for pci_address in pci_addresses:
    _ = run_cmd("python %s --bind=ixgbe %s" % (devbind_script, pci_address))

def setup_open_vswitch(enable_dpdk=True):
  if enable_dpdk:
    socket_mem = 1024
    # Initial DPDK in Open_vSwitch table and allocate 1024 pages in both NUMA
    # nodes.
    _ = run_cmd("ovs-vsctl set Open_vSwitch . other_config:dpdk-init=true "
                "other_config:dpdk-socket-mem=%s,%s "
                "other_config:userspace-tso-enable=true" %
                (socket_mem, socket_mem))
  else:
    # Uninitialize DPDK in Open_vSwitch table.
    _ = run_cmd("ovs-vsctl remove Open_vSwitch . other_config dpdk-init "
                "dpdk-socket-mem userspace-tso-enable")

  # Restart OVS to apply configuraion to Open_vSwitch table.
  _ = run_cmd("systemctl restart ovs-vswitchd")

def setup_dpdk_bridge(bridge, interfaces):
  # Bind the interfaces to vfio-pci.
  device_info = bind_interfaces_to_dpdk(interfaces)
  uplink_bridge = get_uplink_bridge(bridge)

  # Create externally managed bridges to use with DPDK.
  _ = run_cmd("ovs-vsctl add-br %s -- set bridge %s datapath_type=netdev -- "
              "br-set-external-id %s external true" % (bridge, bridge, bridge))

  _ = run_cmd("ovs-vsctl add-br %s -- set bridge %s datapath_type=netdev -- "
              "br-set-external-id %s external true" %
              (uplink_bridge, uplink_bridge, uplink_bridge))

  # Connect the two bridges
  uplink_port = get_uplink_port(bridge)
  uplink_peer_port = get_uplink_peer_port(bridge)
  _ = run_cmd("ovs-vsctl add-port %s %s -- set interface %s type=patch options:peer=%s" %
              (uplink_bridge, uplink_port, uplink_port, uplink_peer_port))
  _ = run_cmd("ovs-vsctl add-port %s %s -- set interface %s type=patch options:peer=%s" %
              (bridge, uplink_peer_port, uplink_peer_port, uplink_port))

  intf_cmd = ""
  if len(interfaces) > 1:
    # Create a bond if the bridge has multiple interfaces.
    bond_name = get_bond(bridge)
    intf_cmd = "ovs-vsctl add-bond %s %s %s" % (uplink_bridge, bond_name,
                                                " ".join(interfaces))
    for intf in interfaces:      
      intf_cmd += get_intf_dpdk_command(intf, device_info[intf]["pci_address"])
  else:
    # Single physical interface in the bridge.
    intf = interfaces[0]
    intf_cmd = "ovs-vsctl add-port %s %s" % (uplink_bridge, intf)
    intf_cmd += get_intf_dpdk_command(intf, device_info[intf]["pci_address"])

  _ = run_cmd(intf_cmd)

def delete_dpdk_bridge(bridge, interfaces):
  uplink_bridge = get_uplink_bridge(bridge)
  pci_addresses = [get_interface_pci_address(intf) for intf in interfaces]

  # Delete all ports attached to the bridge.
  bridge_ports = list_ports(bridge)
  for port in bridge_ports:
    _ = run_cmd("ovs-vsctl del-port %s" % port)
  bridge_ports = list_ports(uplink_bridge)
  for port in bridge_ports:
    _ = run_cmd("ovs-vsctl del-port %s" % port)

  # Wait for bond to get deleted.
  time.sleep(10)

  # Bind interfaces back to kernel
  bind_interfaces_to_kernel(pci_addresses)

  # Delete bridge.
  _ = run_cmd("ovs-vsctl del-br %s" % bridge)
  _ = run_cmd("ovs-vsctl del-br %s" % uplink_bridge)

def configure_arp_dhcp_flows(bridge):
  uplink_bridge = get_uplink_bridge(bridge)
  uplink_port = get_uplink_port(bridge)
  vxlan_port = get_arp_dhcp_port(bridge)
  _ = run_cmd("ovs-ofctl add-flow %s table=0,priority=2,udp,in_port=%s,tp_dst=67,actions=output:%s" %
              (uplink_bridge, uplink_port, vxlan_port))
  _ = run_cmd("ovs-ofctl add-flow %s table=0,priority=2,udp,in_port=%s,tp_dst=68,actions=output:%s" %
              (uplink_bridge, vxlan_port, uplink_port))
  _ = run_cmd("ovs-ofctl add-flow %s table=0,priority=1,arp,in_port=%s,actions=NORMAL,output:%s" %
              (uplink_bridge, uplink_port, vxlan_port))

def create_dpdk_dvs(bridge, interfaces):
  # Validate that the bridge does not exist.
  uplink_bridge = get_uplink_bridge(bridge)
  bridges = list_bridges()

  if bridge in bridges:
    usage(err="Bridge %s already exists" % bridge)

  if uplink_bridge in bridges:
    usage(err="Bridge %s already exists" % uplink_bridge)

  # Setup Open_vSwitch table.
  setup_open_vswitch()

  # Setup Bridge.
  setup_dpdk_bridge(bridge, interfaces)

def delete_dpdk_dvs(bridge, interfaces):
  # Validate that the bridge exists.
  bridges = list_bridges()
  if bridge not in bridges:
    usage(err="Bridge %s does not exist" % bridge)

  # Cleanup bridge.
  delete_dpdk_bridge(bridge, interfaces)

  # Remove DPDK specific configuration from Open_vSwitch table
  setup_open_vswitch(enable_dpdk=False)

def configure_dpdk_dvs(bridge, ip, network, gateway, bridge_tag, acropolis_ip):
  bridges = list_bridges()
  uplink_bridge = get_uplink_bridge(bridge)

  if bridge not in bridges:
    usage(err="Bridge %s does not exist" % bridge)

  if uplink_bridge not in bridges:
    usage(err="Bridge %s does not exist" % uplink_bridge)

  # Set bridge tag for interface on tagged VLANs
  if bridge_tag:
    _ = run_cmd("ovs-vsctl set Port %s tag=%d" % (uplink_bridge, bridge_tag))
    
  # Setup port for ARP, DHCP packets
  vxlan_port = get_arp_dhcp_port(bridge)
  _ = run_cmd("ovs-vsctl --may-exist add-port %s %s -- set Interface %s type=vxlan options:remote_ip=%s" %
              (uplink_bridge, vxlan_port, vxlan_port, acropolis_ip))
  _ = run_cmd("ovs-ofctl mod-port %s %s no-flood" % (uplink_bridge, vxlan_port))

  # Assign IP adress to bridge
  netmask = str(ipaddress.IPv4Network(unicode(network)).netmask)
  _ = run_cmd("ip addr flush dev %s" % uplink_bridge)
  _ = run_cmd("ip addr add %s/%s brd + dev %s" % (ip, netmask, uplink_bridge))
  _ = run_cmd("ip link set %s up" % uplink_bridge)
  
  # Create PBR policy
  _ = run_cmd("ip route add %s dev %s src %s table 1001" % (network, uplink_bridge, ip))
  _ = run_cmd("ip route add default via %s dev %s table 1001" % (gateway, uplink_bridge))
  _ = run_cmd("ip rule add from %s table 1001" % ip)

  # Create userspace route
  _ = run_cmd("ovs-appctl ovs/route/add %s/32 %s %s" % (acropolis_ip, uplink_bridge, gateway))

  configure_arp_dhcp_flows(bridge)

def unconfigure_dpdk_dvs(bridge):
  bridges = list_bridges()

  uplink_bridge = get_uplink_bridge(bridge)
  if bridge not in bridges:
    usage(err="Bridge %s does not exist" % bridge)

  if uplink_bridge not in bridges:
    usage(err="Bridge %s does not exist" % uplink_bridge)

  # Remove routing table rules
  _ = run_cmd("ip route flush table 1001")
  _ = run_cmd("ip addr flush dev %s" % (uplink_bridge))

  # Remove PBR policy
  _ = run_cmd("ip rule del table 1001")

def parse_create_dpdk_dvs(argv):
  parser = argparse.ArgumentParser(description="Create DPDK enabled DVS")
  parser.add_argument('--bridge-name', required=True, type=str)
  parser.add_argument('--bridge-interfaces', required=True, type=str, nargs="+")

  args = parser.parse_args(argv[2:])
  bridge = args.bridge_name
  interfaces = args.bridge_interfaces

  create_dpdk_dvs(bridge, interfaces)

def parse_delete_dpdk_dvs(argv):
  parser = argparse.ArgumentParser(description="Delete DPDK enabled DVS")
  parser.add_argument('--bridge-name', required=True, type=str)
  parser.add_argument('--bridge-interfaces', required=True, type=str, nargs="+")
  
  args = parser.parse_args(argv[2:])
  bridge = args.bridge_name
  interfaces = args.bridge_interfaces

  delete_dpdk_dvs(bridge, interfaces)

def parse_configure_dpdk_dvs(argv):
  parser = argparse.ArgumentParser(description="Configure DPDK DVS")
  parser.add_argument('--bridge-name', required=True, type=str)
  parser.add_argument('--bridge-ip', required=True, type=str)
  parser.add_argument('--bridge-network', required=True, type=str)
  parser.add_argument('--bridge-gateway', required=True, type=str)
  parser.add_argument('--bridge-tag', default=0, type=int)
  parser.add_argument('--acropolis-master', required=True, type=str)

  args = parser.parse_args(argv[2:])
  bridge = args.bridge_name
  ip = args.bridge_ip
  network = args.bridge_network
  gateway = args.bridge_gateway
  acropolis_ip = args.acropolis_master
  bridge_tag = args.bridge_tag

  validate_ipv4_address(ip)
  validate_ipv4_network(network)
  validate_ipv4_address(gateway)
  validate_ipv4_address(acropolis_ip)
  validate_bridge_tag(bridge_tag)

  configure_dpdk_dvs(bridge, ip, network, gateway, bridge_tag, acropolis_ip)

def parse_unconfigure_dpdk_dvs(argv):
  parser = argparse.ArgumentParser(description="Unconfigure DPDK DVS")
  parser.add_argument('--bridge-name', required=True, type=str)

  args = parser.parse_args(argv[2:])
  bridge = args.bridge_name

  unconfigure_dpdk_dvs(bridge)

commands = {
  "--create_dpdk_dvs": parse_create_dpdk_dvs,
  "--delete_dpdk_dvs": parse_delete_dpdk_dvs,
  "--configure_dpdk_dvs": parse_configure_dpdk_dvs,
  "--unconfigure_dpdk_dvs": parse_unconfigure_dpdk_dvs
}

def main(argv):
  if len(argv) < 2:
    usage(err="Missing command")
  cmd = argv[1]
  if cmd not in commands.keys():
    usage(err="Unsupported command")
  commands[cmd](argv)

if __name__ == "__main__":
  main(sys.argv)
