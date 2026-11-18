from lxml import etree
def import_xml(upload):
    return etree.fromstring(upload.read())
