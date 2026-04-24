#!/usr/bin/env python3
# coding:utf8
import sqlite3

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None
import argparse
import re
import exifread


def get_pdf_meta(file_name):
    if not PdfReader:
        print("[-] Library 'pypdf' not found.")
        return
    try:
        reader = PdfReader(file_name)
        doc_info = reader.metadata
        if doc_info:
            for info in doc_info:
                print("[+] " + info + " " + str(doc_info[info]))
        else:
            print("[-] No metadata found.")
    except Exception as e:
        print(f"[-] Error reading PDF: {e}")


def get_strings(file_name):
    with open(file_name, "rb") as file:
        content = file.read()
    _re = re.compile(r"[\S\s]{4,}")
    for match in _re.finditer(content.decode("utf8", "backslashreplace")):
        print(match.group())


def _convert_to_degress(value):
    """
    Helper function to convert the GPS coordinates stored in the EXIF to degress in float format
    :param value:
    :type value: exifread.utils.Ratio
    :rtype: float
    """
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)
    return d + (m / 60.0) + (s / 3600.0)


def get_gps_from_exif(file_name):
    with open(file_name, "rb") as file:
        exif = exifread.process_file(file)
    if not exif:
        print("Aucune métadonnée EXIF.")
    else:
        latitude = exif.get("GPS GPSLatitude")
        latitude_ref = exif.get("GPS GPSLatitudeRef")
        longitude = exif.get("GPS GPSLongitude")
        longitude_ref = exif.get("GPS GPSLongitudeRef")
        altitude = exif.get("GPS GPSAltitude")
        altitude_ref = exif.get("GPS GPSAltitudeRef")
        if latitude and longitude and latitude_ref and longitude_ref:
            lat = _convert_to_degress(latitude)
            long = _convert_to_degress(longitude)
            if str(latitude_ref) != "N":
                lat = 0 - lat
            if str(longitude_ref) != "E":
                long = 0 - long
            print("LAT : " + str(lat) + " LONG : " + str(long))
            print("http://maps.google.com/maps?q=loc:%s,%s" % (str(lat), str(long)))
            if altitude and altitude_ref:
                alt_ = altitude.values[0]
                alt = alt_.num / alt_.den
                if altitude_ref.values[0] == 1:
                    alt = 0 - alt
                print("ALTITUDE : " + str(alt))


def get_exif(file_name):
    with open(file_name, "rb") as file:
        exif = exifread.process_file(file)
    if not exif:
        print("Aucune métadonnée EXIF.")
    else:
        for tag in exif.keys():
            print(tag + " " + str(exif[tag]))

#Récupération des cookies
def get_firefox_history(places_db):
    try:
        conn  = sqlite3.connect(places_db)
        cursor = conn.cursor()
        cursor.execute("select url, datetime(last_visit_date/1000000,"
                       " \"unixepoch\") from moz_places, moz_historyvisits where visit_count > 0 and moz_places.id == moz_historyvisits.id")
        #cursor.fetchall()
        header = "<!DOCTYPE html><head><style>table, th, tr, td{border:1px solid green;}</style>\
        </head><body><table><tr><th>URL</th><th>Date</th></tr>"
        with open("rapport_firefox.html", "a") as f:
            f.write(header)
            for row in cursor:
                url = str(row[0])
                date = str(row[1])
                f.write("<tr><td><a href='" + url + "'>"+ url + "</td><td>" + date + "</td></tr>")
            footer = "</table></body></html>"
            f.write(footer)
    except Exception as e:
        print("[-] Erreur : " + str(e))
        exit(1)


#Les cookies
def get_firefox_cookies(cookies_sqlite):
    try:
        conn = sqlite3.connect(cookies_sqlite)
        cursor = conn.cursor()
        cursor.execute("SELECT name, value, host FROM moz_cookies")
        #print(cursor.fetchall())
        header = "<!DOCTYPE html><head><style>table, th, tr, td{border:1px solid green;}</style>\
                </head><body><table><tr><th>Nom Cookies</th><th>Valeur Cookies</th><th>Hôte</th></tr>"
        with open("cookies_firefox.html", "a") as f:
            f.write(header)
            for row in cursor:
                name = str(row[0])
                value = str(row[1])
                host = str(row[2])
                f.write("<tr><td>" + name +"</td><td>" + value + "</td><td>"+ host +"</td></tr>")
            footer = "</table></body></html>"
            f.write(footer)

    except Exception as e:
        print("[-] Erreur : " + str(e))
        exit(1)


parser = argparse.ArgumentParser(description="Outil de forensique")
parser.add_argument("-pdf", dest="pdf", help="Chemin du fichier PDF", required=False)
parser.add_argument("-str", dest="str", help="Chemin du fichier auquel récupérer les chaînes de caractères",
                    required=False)
parser.add_argument("-exif", dest="exif", help="Chemin de l'image pour la récupération des métadonnées exif",
                    required=False)
parser.add_argument("-gps", dest="gps", help="Récupère les coordonées GPS depuis l'image (si existantes)",
                    required=False)
parser.add_argument("-fh", dest="fhistory", help="Récupère les sites visités dans Firefox à partir du fichier places.sqlite",
                    required=False)
parser.add_argument("-fc", dest="fcookies", help="Récupère les cookies dans Firefox à partir du fichier cookies.sqlite",
                    required=False)



args = parser.parse_args()

if args.pdf:
    get_pdf_meta(args.pdf)

if args.str:
    get_strings(args.str)

if args.exif:
    get_exif(args.exif)

if args.gps:
    get_gps_from_exif(args.gps)

if args.fhistory:
    get_firefox_history(args.fhistory)

if args.fcookies:
    get_firefox_cookies(args.fcookies)
