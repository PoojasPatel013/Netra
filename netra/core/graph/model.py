from neomodel import (
    StructuredNode,
    StringProperty,
    RelationshipTo,
    DateTimeProperty,
    JSONProperty,
)


class NetraNode(StructuredNode):
    __abstract_node__ = True
    created_at = DateTimeProperty(default_now=True)
    tags = JSONProperty(default=[])


class CloudAsset(NetraNode):
    resource_id = StringProperty(unique_index=True, required=True)
    provider = StringProperty(choices={"AWS": "AWS", "GCP": "GCP", "AZURE": "AZURE"})
    service = StringProperty()
    region = StringProperty()


class Domain(NetraNode):
    name = StringProperty(unique_index=True, required=True)
    registrar = StringProperty()

    # Relationships
    resolves_to = RelationshipTo("IPAddress", "RESOLVES_TO")
    hosted_on = RelationshipTo("CloudAsset", "HOSTED_ON")
    subdomain_of = RelationshipTo("Domain", "SUBDOMAIN_OF")


class IPAddress(NetraNode):
    address = StringProperty(unique_index=True, required=True)
    version = StringProperty(default="IPv4")

    # Relationships
    belongs_to_block = RelationshipTo("IPBlock", "PART_OF_BLOCK")


class IPBlock(NetraNode):
    cidr = StringProperty(unique_index=True, required=True)
    asn = StringProperty()
    organization = StringProperty()


class Certificate(NetraNode):
    fingerprint = StringProperty(unique_index=True, required=True)
    common_name = StringProperty()
    issuer = StringProperty()

    valid_for = RelationshipTo("Domain", "VALID_FOR")
