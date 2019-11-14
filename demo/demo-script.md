# One command demo execution
./deploy_peers.py peers.json

# One command demo cleanup
./withdraw_peers.py peers.json

# Configure individual peer interface
./config_peer_interface.py GigabitEthernet0/0/0/0 "Peering with AS65002" 192.168.0.1 255.255.255.0 ssh://admin:admin@198.18.1.11

# Validate individual peer interface
./validate_peer_interface.py asbr1 GigabitEthernet0/0/0/0

# Configure individual BGP peer
./config_bgp_peer.py 65001 192.168.0.2 65002 EBGP ssh://admin:admin@198.18.1.11

# Validate individual BGP peer
./validate_bgp_peer.py asbr1 192.168.0.2

# Remove individual peer interface
./remove_peer_interface.py GigabitEthernet0/0/0/0 ssh://admin:admin@198.18.1.11

# Remove individual BGP peer
./remove_bgp_peer.py 65001 192.168.0.2 ssh://admin:admin@198.18.1.11
