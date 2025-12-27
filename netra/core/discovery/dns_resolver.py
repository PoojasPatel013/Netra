import aiodns
from netra.core.graph.model import Domain, IPAddress


class DNSResolver:
    def __init__(self):
        self.resolver = aiodns.DNSResolver()

    async def resolve(self, domain_name: str):
        """
        Resolves a domain name and updates the Graph.
        """
        print(f"🔎 Resolving {domain_name}...")

        # 1. Create/Get Domain Node
        domain_node = Domain.nodes.first_or_create(name=domain_name)

        try:
            # 2. Perform DNS Lookup
            result = await self.resolver.query(domain_name, "A")

            for r in result:
                ip_addr = r.host
                print(f"   -> Found IP: {ip_addr}")

                # 3. Create/Get IP Node
                ip_node = IPAddress.nodes.first_or_create(address=ip_addr)

                # 4. Link Access (Graph Edge)
                # neomodel connect
                domain_node.resolves_to.connect(ip_node)

            print(f"✅ Graph Updated for {domain_name}")
            return True

        except Exception as e:
            print(f"❌ Resolution failed for {domain_name}: {e}")
            return False
