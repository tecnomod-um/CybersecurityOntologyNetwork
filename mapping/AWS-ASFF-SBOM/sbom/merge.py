import json
from rdflib import Graph, Namespace, URIRef, Literal, BNode
from rdflib.namespace import RDF, RDFS, XSD

# Load original graph
bom_graph = Graph()
bom_graph.parse("sbom_graph.nt", format="nt")

# Load JSON SBOM
with open('sbom.json') as f:
    sbom = json.load(f)

# Define URI for BOM node
bom_uri = "https://data.siemens-energy.com/cybersec/bom/urn%3Auuid%3Aa4d3d687-b56f-4ec9-ae2a-daf44203e9c2"
bom_node = URIRef(bom_uri)

# Namespaces
SE_VOCAB = Namespace("https://vocab.siemens-energy.com/cybersec/")
SE_VOCAB_COMPONENT = Namespace("https://vocab.siemens-energy.com/cybersec/component/")
SE_DATA_COMPONENT = Namespace("https://data.siemens-energy.com/cybersec/component/")
SE_DATA_LICENSE = Namespace("https://data.siemens-energy.com/cybersec/license/")
SE_DATA_EXTERNAL_REFERENCE = Namespace("https://data.siemens-energy.com/cybersec/externalreference/")
SCHEMA = Namespace("https://schema.org/")

# New graph for component data
g = Graph()
g.bind("se_sec_vocab", SE_VOCAB)
g.bind("se_sec_vocab_component", SE_VOCAB_COMPONENT)
g.bind("se_sec_data_component", SE_DATA_COMPONENT)
g.bind("se_sec_data_license", SE_DATA_LICENSE)
g.bind("se_sec_data_external_reference", SE_DATA_EXTERNAL_REFERENCE)
g.bind("schema", SCHEMA)
g.bind("rdfs", RDFS)


def add_component(comp, parent_node=None):
    purl = comp.get("purl")
    if not purl:
        return

    comp_uri = URIRef(SE_DATA_COMPONENT + purl)

    # Core component triples
    g.add((comp_uri, RDF.type, URIRef(SE_VOCAB_COMPONENT + comp.get("type", "Component"))))
    g.add((comp_uri, SE_VOCAB.purl, Literal(purl, datatype=XSD.anyURI)))
    g.add((comp_uri, RDFS.label, Literal(comp.get("name", purl), datatype=XSD.string)))
    g.add((comp_uri, SE_VOCAB["bom-ref"], Literal(comp.get("bom-ref", ""), datatype=XSD.string)))
    g.add((comp_uri, SE_VOCAB.componentVersion, Literal(comp.get("version", ""), datatype=XSD.string)))

    if comp.get("author"):
        g.add((comp_uri, SCHEMA.author, Literal(comp["author"], datatype=XSD.string)))

    if comp.get("description"):
        g.add((comp_uri, SCHEMA.description, Literal(comp["description"], datatype=XSD.string)))

    # Licenses
    for lic in comp.get("licenses", []):
        lic_id = lic.get("license", {}).get("id")
        if lic_id:
            lic_uri = URIRef(SE_DATA_LICENSE + lic_id)
            g.add((comp_uri, SE_VOCAB.license, lic_uri))

    # External references
    for ref in comp.get("externalReferences", []):
        url = ref.get("url")
        if not url:
            continue
        ref_uri = URIRef(SE_DATA_EXTERNAL_REFERENCE + url)
        g.add((comp_uri, SE_VOCAB.externalReference, ref_uri))
        g.add((ref_uri, RDF.type, URIRef(SE_VOCAB + "externalReference/" + ref.get("type", "Reference"))))
        g.add((ref_uri, SE_VOCAB.url, Literal(url, datatype=XSD.anyURI)))
        if ref.get("comment"):
            g.add((ref_uri, SE_VOCAB.comment, Literal(ref["comment"], datatype=XSD.string)))

        for h in ref.get("hashes", []):
            hash_blank = BNode()
            g.add((ref_uri, SE_VOCAB.hash, hash_blank))
            g.add((hash_blank, SE_VOCAB.algorithm, Literal(h.get("alg", ""), datatype=XSD.string)))
            g.add((hash_blank, SE_VOCAB.content, Literal(h.get("content", ""), datatype=XSD.string)))

    # Properties
    for prop in comp.get("properties", []):
        name = prop.get("name")
        value = prop.get("value")
        if name and value:
            g.add((comp_uri, SE_VOCAB[name], Literal(value, datatype=XSD.string)))

    # Link to parent (BOM or parent component)
    if parent_node:
        g.add((parent_node, SE_VOCAB.hasComponent, comp_uri))
    else:
        g.add((bom_node, SE_VOCAB.hasComponent, comp_uri))

    # Recursively add nested components
    for nested in comp.get("components", []):
        add_component(nested, parent_node=comp_uri)


# Map all top-level components
for c in sbom.get("components", []):
    add_component(c)

# Merge and serialize
bom_graph += g
bom_graph.serialize(destination="combined.nt", format="nt")
