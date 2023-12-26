import argparse

from pynmeagps.nmeareader import NMEAReader
from pynmeagps.nmeamessage import NMEAMessage
import pynmeagps.exceptions as nme
from pynmeagps.nmeatypes_core import (
    ERR_LOG,
    ERR_RAISE,
    GET,
    NMEA_HDR,
    VALCKSUM,
    VALMSGID,
)

def main():
    parser = argparse.ArgumentParser(description='Parse NMEA data from a file and annotate it.')
    parser.add_argument('inputfile', type=str, help='Path to the file containing raw NMEA data')
    parser.add_argument('-o', '--output', action='store_true', help='Output results to a file with the same name suffixed by "-annotated"')
    parser.add_argument('-n', '--num_msg', type=int, help='Number of lines to parse')

    args = parser.parse_args()

    print(f"\nOpening file {args.inputfile}...\n")
    msgcount = 0
    errcount = 0

    try:
        with open(args.inputfile, 'rb') as file:
            if args.output:
                output_filename = args.inputfile.rsplit('.', 1)[0] + '-annotated.' + args.inputfile.rsplit('.', 1)[1]
                outputfile = open(output_filename, 'w')

            for line in file:
                # parse
                error = None
                parsed_data = None
                try:
                    parsed_data = NMEAReader.parse(line, msgmode=GET, validate=VALCKSUM+VALMSGID)
                except (
                    nme.NMEAMessageError,
                    nme.NMEATypeError,
                    nme.NMEAParseError,
                    nme.NMEAStreamError,
                ) as err:
                    error = str(err)
                # message object back to string
                if parsed_data is None:
                    output_line = line.decode('utf-8', errors='replace').strip()
                    if output_line is None:
                        output_line=''
                else:
                    output_line = str(parsed_data)
                # append error
                if error is not None:
                    errcount += 1
                    output_line += ' (' + error + ')'
                # write to file or stdout
                if args.output:
                    outputfile.write(output_line + "\n")
                else:
                    print(output_line)
                
                msgcount += 1
                if args.num_msg is not None and msgcount > args.num_msg:
                    print(f"\nReached specified maximum message count {args.num_msg}, stopping...")
                    break
    except FileNotFoundError:
        print(f"Error: File '{args.inputfile}' not found.")

    if args.output:
         outputfile.close()

    print(f"\nProcessing Complete. {msgcount} message(s) processed, {errcount} message(s) failed to parse")

if __name__ == "__main__":
    main()