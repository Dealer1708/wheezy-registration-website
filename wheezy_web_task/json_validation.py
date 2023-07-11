import json

file_path = "temp/temp.json"


def validation_func(file_path):
    unique_uuids = set()
    unique_cads = set()
    unique_codes_community = set()
    unique_codes_residence = set()

    with open(file_path, "r") as read_file:
        object = json.load(read_file)
        data = object["data"]
        for idx, item in enumerate(data):
            unit_names = item["names"]
            classifier_codes = item["classifier_codes"]
            parent_units = item["parent_units"]

            uuid = item["uuid"]
            cad_code = item["cadastral_code"]
            type_id = item["type"]

            if type_id != "region":
                last_parent_units = parent_units[-1]
            if uuid not in unique_uuids:
                unique_uuids.add(uuid)
            else:
                add_error(idx, f"this uuid {uuid} is duplicate")

            if type_id == "community":
                if cad_code != "":
                    add_error(idx, f"cadastral code should not exist")
                check_unique_codes(idx, classifier_codes,
                                   unique_codes_community)

            elif type_id == "residence":
                if cad_code == "":
                    add_error(
                        idx, f" cadastral code for this {uuid} is missing")
                else:
                    if cad_code not in unique_cads:
                        unique_cads.add(cad_code)
                    else:
                        if cad_code != "---":
                            add_error(
                                idx, f"cadastral code {cad_code}\
                                for this uuid {uuid} is duplicate"
                            )
                check_unique_codes(idx, classifier_codes,
                                   unique_codes_residence)

            try:
                if type_id != "region":
                    if last_parent_units["end_date"] != "":
                        check_unit_names = item["names"]
                        check_class_codes = item["classifier_codes"]

                        if check_unit_names[-1]['end_date'] == ""\
                                or check_class_codes[-1]['end_date'] == "":
                            add_error(
                                idx, f"parent uuid {parent_uuid}\
                                has end date but unit names and\
                                classifier codes don't"
                            )
            except Exception as ex:
                add_error(idx, f"the exception {ex}")

            try:
                for unit in unit_names + classifier_codes + parent_units:
                    start_date = unit["start_date"]
                    end_date = unit["end_date"]
                    if start_date and end_date and start_date > end_date:
                        add_error(
                            idx, f"wrong position\
                            of dates for uuid {uuid}"
                        )
            except Exception as ex:
                add_error(idx, f"wrong position of dates for uuid {uuid}")

            try:
                for p1 in parent_units:
                    parent_uuid = p1["uuid"]
                    if parent_uuid not in unique_uuids:
                        add_error(
                            idx, f"parent uuid {parent_uuid}\
                                missing for the uuid {uuid}"
                        )
            except Exception as ex:
                add_error(
                    idx, f"parent uuid {parent_uuid}\
                        missing for the uuid {uuid}"
                )
            try:
                for n in unit_names:
                    name = n["name"]
                    if not name:
                        add_error(idx, f"no name in this uuid {uuid}")
            except Exception as ex:
                add_error(idx, f"no name in this uuid {uuid}")

    return error_list


error_list = []


def add_error(idx, error):
    error = f"In index {idx} {error}"
    error_list.append(error)


def check_unique_codes(index, codes, code_set):
    for i in codes:
        code = i["code"]
        if code not in code_set:
            code_set.add(code)
        elif len(code) not in (7, 8):
            add_error(index, f"this code {code} has invalid length")
        else:
            add_error(index, f"this code {code} is duplicate")