import json
import urllib.parse
from rdflib import Graph, Literal, Namespace, RDF, XSD, URIRef

# Cargar el JSON
with open('nvdcve-1.1-2025.json', 'r') as f:
    data = json.load(f)

# Inicializar el grafo
g = Graph()

# Definir prefijos
SE_SEC_VOCAB = Namespace("https://vocab.siemens-energy.com/cybersec/")
SE_SEC_NVD_VOCAB = Namespace("https://ontology.siemens-energy.com/nvd/")
SE_SEC_DATA = Namespace("https://data.siemens-energy.com/cybersec/")
SCHEMA = Namespace("https://schema.org/")
RDFS = Namespace("http://www.w3.org/2000/01/rdf-schema#")

# Enlazar namespaces
g.bind("se_sec_vocab", SE_SEC_VOCAB)
g.bind("se_sec_nvd_vocab", SE_SEC_NVD_VOCAB)
g.bind("se_sec_data", SE_SEC_DATA)
g.bind("schema", SCHEMA)
g.bind("rdfs", RDFS)

# Mapear CVE Record
record_uri = URIRef(f"{SE_SEC_DATA}cve_record/{urllib.parse.quote(data['CVE_data_type'] + '-' + data['CVE_data_format'] + '-' + data['CVE_data_version'] + '-' + str(data['CVE_data_numberOfCVEs']) + '-' + data['CVE_data_timestamp'])}")
g.add((record_uri, RDF.type, SE_SEC_NVD_VOCAB.CVE_Record))
g.add((record_uri, SE_SEC_NVD_VOCAB.CVE_data_type, Literal(data['CVE_data_type'], datatype=XSD.string)))
g.add((record_uri, SE_SEC_NVD_VOCAB.CVE_data_format, Literal(data['CVE_data_format'], datatype=XSD.string)))
g.add((record_uri, SE_SEC_NVD_VOCAB.CVE_data_version, Literal(data['CVE_data_version'], datatype=XSD.string)))
g.add((record_uri, SE_SEC_NVD_VOCAB.CVE_data_numberOfCVEs, Literal(data['CVE_data_numberOfCVEs'], datatype=XSD.int)))
g.add((record_uri, SE_SEC_NVD_VOCAB.CVE_data_timestamp, Literal(data['CVE_data_timestamp'], datatype=XSD.dateTime)))

# Mapear CVE Items
for item in data['CVE_Items']:
    cve_id = item['cve']['CVE_data_meta']['ID']
    cve_uri = URIRef(f"{SE_SEC_DATA}cve/{urllib.parse.quote(cve_id)}")
    g.add((cve_uri, RDF.type, SE_SEC_NVD_VOCAB.CVE))
    g.add((cve_uri, SE_SEC_NVD_VOCAB.ID, Literal(cve_id, datatype=XSD.string)))
    g.add((cve_uri, SE_SEC_NVD_VOCAB.assigner, Literal(item['cve']['CVE_data_meta']['ASSIGNER'], datatype=XSD.string)))
    g.add((cve_uri, SE_SEC_NVD_VOCAB.publishedDate, Literal(item['publishedDate'], datatype=XSD.dateTime)))
    g.add((cve_uri, SE_SEC_NVD_VOCAB.lastModifiedDate, Literal(item['lastModifiedDate'], datatype=XSD.dateTime)))

    # Descripción
    for desc in item['cve']['description']['description_data']:
        g.add((cve_uri, SE_SEC_NVD_VOCAB.description, Literal(desc['value'], datatype=XSD.string)))

    # Configurations
    config_uri = URIRef(f"{SE_SEC_DATA}configuration/{urllib.parse.quote(cve_id)}-config")
    g.add((config_uri, RDF.type, SE_SEC_NVD_VOCAB.Configuration))
    g.add((config_uri, SE_SEC_NVD_VOCAB.CVE_data_version, Literal(item['configurations']['CVE_data_version'], datatype=XSD.string)))
    g.add((cve_uri, SE_SEC_NVD_VOCAB.hasConfiguration, config_uri))

    # Nodes
    for i, node in enumerate(item['configurations']['nodes']):
        node_uri = URIRef(f"{SE_SEC_DATA}node/{urllib.parse.quote(cve_id)}-node-{i+1}")
        g.add((node_uri, RDF.type, SE_SEC_NVD_VOCAB.Node))
        g.add((node_uri, SE_SEC_NVD_VOCAB.operator, Literal(node.get('operator', ''), datatype=XSD.string)))
        g.add((node_uri, SE_SEC_NVD_VOCAB.negate, Literal(node.get('negate', False), datatype=XSD.boolean)))
        g.add((config_uri, SE_SEC_NVD_VOCAB.hasNode, node_uri))

        # CPE Match
        for cpe in node.get('cpe_match', []):
            cpe_uri = URIRef(f"{SE_SEC_DATA}cpe/{urllib.parse.quote(cve_id)}-cpe-{urllib.parse.quote(cpe['cpe23Uri'])}")
            g.add((cpe_uri, RDF.type, SE_SEC_NVD_VOCAB.CPEMatch))
            g.add((cpe_uri, SE_SEC_NVD_VOCAB.vulnerable, Literal(cpe['vulnerable'], datatype=XSD.boolean)))
            g.add((cpe_uri, SE_SEC_NVD_VOCAB.cpe23Uri, Literal(cpe['cpe23Uri'], datatype=XSD.string)))
            g.add((node_uri, SE_SEC_NVD_VOCAB.hasCPEMatch, cpe_uri))

    # Impact
    if item['impact']:
        impact_uri = URIRef(f"{SE_SEC_DATA}impact/{urllib.parse.quote(cve_id)}-impact")
        g.add((impact_uri, RDF.type, SE_SEC_NVD_VOCAB.Impact))
        baseMetricV3 = item['impact'].get('baseMetricV3', {})
        cvssV3 = baseMetricV3.get('cvssV3', {})
        g.add((impact_uri, SE_SEC_NVD_VOCAB.baseMetricV3_exploitabilityScore, Literal(baseMetricV3.get('exploitabilityScore', 0), datatype=XSD.decimal)))
        g.add((impact_uri, SE_SEC_NVD_VOCAB.baseMetricV3_impactScore, Literal(baseMetricV3.get('impactScore', 0), datatype=XSD.decimal)))
        g.add((impact_uri, SE_SEC_NVD_VOCAB.baseMetricV3_baseScore, Literal(cvssV3.get('baseScore', 0), datatype=XSD.decimal)))
        g.add((impact_uri, SE_SEC_NVD_VOCAB.baseMetricV3_baseSeverity, Literal(cvssV3.get('baseSeverity', ''), datatype=XSD.string)))
        g.add((cve_uri, SE_SEC_NVD_VOCAB.hasImpact, impact_uri))

# Guardar el grafo
g.serialize(destination='cve_data.ttl', format='turtle')
print("Conversión a RDF completada y guardada en 'cve_data.ttl'")

