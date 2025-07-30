import json
import re
from rdflib import Graph, Literal, Namespace, RDF, URIRef
from rdflib.namespace import XSD
from packaging import version

# Define namespaces
SOFTWARE_VOCAB = Namespace("http://ontologies.siemens-energy.com/software/")
CYBERSEC_DATA = Namespace("https://data.siemens-energy.com/cybersec/")
SCHEMA = Namespace("http://schema.org/")

# Load JSON data
with open('python.json', 'r') as f:
    data = json.load(f)

# Create RDF graph
g = Graph()
g.bind("software_vocab", SOFTWARE_VOCAB)
g.bind("cybersec_data", CYBERSEC_DATA)
g.bind("schema", SCHEMA)

# Regular expression to split dependency strings
dep_regex = re.compile(r"([a-zA-Z0-9_\-]+)\s*([<>=!]+)\s*([\d\.]+)")

# Parse JSON data and add to RDF graph
for package in data['installed']:
    metadata = package['metadata']
    package_uri = CYBERSEC_DATA[f"package/{metadata['name']}"]
    print(package_uri)

    g.add((package_uri, RDF.type, SOFTWARE_VOCAB.Software_package))
    g.add((package_uri, SCHEMA.name, Literal(metadata['name'], datatype=XSD.string)))
    g.add((package_uri, SCHEMA.version, Literal(metadata['version'], datatype=XSD.string)))
    g.add((package_uri, SCHEMA.description, Literal(metadata['description'], datatype=XSD.string)))
    # g.add((package_uri, SCHEMA.author, Literal(metadata['author'], datatype=XSD.string)))
    # g.add((package_uri, SCHEMA.maintainer, Literal(metadata['maintainer_email'], datatype=XSD.string)))
    g.add((package_uri, SCHEMA.programmingLanguage, Literal("Python", datatype=XSD.string)))
    # g.add((package_uri, SCHEMA.requires, Literal(metadata['requires_python'], datatype=XSD.string)))

    # Add dependencies
    if 'requires_dist' in metadata:
        for dep in metadata['requires_dist']:
            match = dep_regex.match(dep)
            if match:
                dep_name, dep_operator, dep_version = match.groups()
                print(dep_name, dep_operator, dep_version)
                dep_uri = CYBERSEC_DATA[f"package/{dep_name}"]
                g.add((package_uri, SOFTWARE_VOCAB.hasDependency, dep_uri))

                parsed_dep_version = version.parse(dep_version)
                # Ignore versions that do not conform to SemVer
                if isinstance(parsed_dep_version, version.Version):
                    version_uri = CYBERSEC_DATA[f"version/{dep_version}"]
                    g.add((dep_uri, SOFTWARE_VOCAB.hasVersion, version_uri))
                    g.add((version_uri, SOFTWARE_VOCAB.version_major, Literal(f"{parsed_dep_version.major}", datatype=XSD.int)))
                    g.add((version_uri, SOFTWARE_VOCAB.version_minor, Literal(f"{parsed_dep_version.minor}", datatype=XSD.int)))
                    g.add((version_uri, SOFTWARE_VOCAB.version_micro, Literal(f"{parsed_dep_version.micro}", datatype=XSD.int)))

                    # print(parsed_dep_version.minor)
                    # print(parsed_dep_version.micro)
                

# Serialize RDF graph to Turtle format
g.serialize(destination='output.ttl', format='turtle')
