# import files
import parse        # functions for parsing web page data
import helper       # helper functions


if __name__ == '__main__':
    finished = False

    while not finished:
        url = input('Please enter an Adobe Security Bulletin URL to parse (or "q" to quit): ')
        url = url.replace("'", "")
        if url.lower() == 'q':
            finished = True
        else:
            try:
                data = parse.parse(url)
                helper.make_json(data)
                print('Your URL has been successfully parsed. Please view the results in the file "output.json".\n')
            except:
                print('Sorry, the URL entered could not be parsed. Please make sure the link is valid.\n')

    print('Thank you for using this parser. Goodbye!')
