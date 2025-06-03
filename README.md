# -_R-Vision т

Задание 1.

 > Провести частичный анализ OVAL файла от компании RHEL
(https://www.redhat.com/security/data/oval/v2/RHEL8/rhel-8.oval.xml.bz2) на
первых 3 уязвимостях (патчах). Определить набор объектов, из которых он
строится. Понять основную логику "работы" данного формата.

Нашел на странице GitHub https://github.com/CISecurity/OVALRepo/tree/master/scripts скрипты связанные с форматои OVAL, обнаружил oval_decomposition.py для обработки большого xml файла, который содержит больше 40-50k строк, поэтму

```Python
import argparse
import os
import xml.etree
from lib_oval import OvalDocument
from xml.etree.ElementTree import ElementTree

import lib_repo


def main():
    """
    Breaks the OVAL file into its constituent elements and writes each of those into the repository
    """

    parser = argparse.ArgumentParser(
        description=
        'Separates an OVAL file into its component parts and saves them to the repository.'
    )
    options = parser.add_argument_group('options')
    options.add_argument('-f',
                         '--file',
                         required=True,
                         help='The name of the source file')
    options.add_argument('-v',
                         '--verbose',
                         required=False,
                         action="store_true",
                         help='Enable more verbose messages')
    args = vars(parser.parse_args())

    filename = args['file']
    if args['verbose']:
        verbose = True
    else:
        verbose = False

    decompose(filename, verbose)


def decompose(filename, verbose):
    oval = OvalDocument(None)

    if not oval.parseFromFile(filename):
        print("\n >> Unable to parse source file '{0}':  no actions taken".
              format(filename))
        return

    deflist = oval.getDefinitions()
    #    if not deflist or deflist is None or len(deflist) < 1:
    #        print("\n ## Error:  this document does not contain any OVAL definitions.  No further action will be taken")
    #        return

    if verbose:
        print(" Number of definitions to process: ", len(deflist))

    repository_root = lib_repo.get_repository_root_path()

    writeFiles(deflist, repository_root, verbose)
    writeFiles(oval.getTests(), repository_root, verbose)
    writeFiles(oval.getObjects(), repository_root, verbose)
    writeFiles(oval.getStates(), repository_root, verbose)
    writeFiles(oval.getVariables(), repository_root, verbose)


#     for test in deflist:
#         filepath = test.constructFilePath()
#         if not filepath or filepath is None:
#             # Some sort of error.  Add this element to our problem list
#             print("## Error with element ", test.getId())
#         elif os.path.exists(filepath):
#             # Add it to the list of possible conflicts
#             print("## File exists: ", filepath)
#         else:
#             print("  ## New file: ", filepath)
#

#For each file path, see if a file already exists in the repository
#  Should it be a collision if the file contents match?
#  How about if the file contents don't match, but the XML attributes do?
#File name collisions?  Show the user
#  For each file, show the current and new element
#  Prompt for possible actions:  skip, update, retain, cancel
#  If updating, make sure the version is set properly


def writeFiles(element_list, repo_root, verbose=False):
    if not element_list or element_list is None:
        return

    for element in element_list:
        e = element.getElement()
        filepath = lib_repo.get_element_repository_path(e)
        if filepath and filepath is not None:
            writeFile(filepath, element, verbose)


def writeFile(path, element, verbose=False):

    if verbose:
        if os.path.exists(path):
            # TODO  Determine if the element has not changed
            print("## Overwrite existing file: ", path)
        else:
            print("@@ Creating new file: ", path)

    # Get the namespace of this element
    namespace = element.getNamespace()
    # Register this namespace with the parser as the default namespace
    xml.etree.ElementTree.register_namespace("", namespace)
    xml.etree.ElementTree.register_namespace(
        "oval", "http://oval.mitre.org/XMLSchema/oval-common-5")
    xml.etree.ElementTree.register_namespace(
        "oval-def", "http://oval.mitre.org/XMLSchema/oval-definitions-5")
    xml.etree.ElementTree.register_namespace(
        "xsi", "http://www.w3.org/2001/XMLSchema-instance")

    e = element.getElement()

    # Fix up the element so it will print nicely
    OvalDocument.indent(e)
    # Create a new ElementTree with this element as the root
    tree = ElementTree(e)
    # And finally, write the full tree to a file not including the xml declaration
    parent = os.path.dirname(path)
    if not os.path.isdir(parent):
        try:
            os.makedirs(parent, 0o0755, True)
            os.chmod(parent, 0o0755)
        except:
            return False

    # WKM CHANGE
    tree.write(path, "UTF-8", False, None, "xml")
    os.chmod(path, 0o0664)
    return True


if __name__ == '__main__':
    main()
```
