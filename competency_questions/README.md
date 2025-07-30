# Competency questions

## Competency questions from Markus Rompe

(Questions 3 to 7 were defined at the beggining, questions 1 and 2 are newer and hence more important)

1. Which import ID I can reach for a vulnerability defined in a NVD database?
2. Which toplevel imports I have in my Python environment? (Python.json)?
3. The Vulnerability "CVE-2019-14322" is affecting which components? Expected Result: all higher level components which include the CVE-2019-14322 "werkzeug" python library in version below 0.15.5
4. Which component prevents that this artifact (docker-image) can be updated to a version without known vulnerabilities with minimal changes? Expected Result: Component which is used in the project but do not support any version without the vulnerability. This problem is when in higher level import is not maintained anymore or at time, so that an update to the lower level component which is already fixed is not possible.
5. Which components can be updated in this project? Expected Result: List of most actual software components for a the given project. This query gives a total amount of technical debt of a project, since updates and upgrades require testing, clearing, documentation updates, deployment or distribution.
6. Which OSS component are cleared and used in multiple projects? Expected Result: List of projects which are using the specified component. Usage of OSS component reduce development time but add maintenance cost for clearing, scanning or deployment costs. Other soft factors is existing knowledge about the component. When a common component is used the overall maintenance costs are distributed over the different business users.
7. Will an upgrade to vulnerability free component of the project change the license conditions? Expected Result: List of Versions, vulnerabilities and Licenses for given component. If the component require new legal conditions to be able to be patched, the impact must be evaluated.

## Comments from Mikel

1. Done.
2. Done.
3. This is another version of question 1.
4. With the currently provided sample data there is no answering this questions. We would need chronological SBOMs with different versions for each component?
5. It is not possible to know from the SBOMs which components can be updated, since the SBOM only has a piined version: how do we know if there is a new version available?
6. Project information has not been provided with the SBOMs.
7. We would need chronological SBOMs again, to check different versions.