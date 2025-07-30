# Jupyter Notebook SPARQL

## Install Jupypter notebook

pip install notebook

## Libraries

### SPARQL wrapper

pip install SPARQLWrapper

### SPARQL kernel

pip install sparqlkernel
jupyter sparqlkernel install --user $USER

### SPARQL graphs

pip install yfiles_jupyter_graphs_for_sparql==0.9.0rc1

from SPARQLWrapper import SPARQLWrapper
from yfiles_jupyter_graphs_for_sparql import SparqlGraphWidget

g = SparqlGraphWidget(wrapper=SPARQLWrapper("http://dbpedia.org/sparql"))

q = """
    SELECT ?sub ?p ?ob
    WHERE {
        ?sub ?p ?ob .
    }
    """
g.show_query(q)

## Exec notebook

jupyter notebook
