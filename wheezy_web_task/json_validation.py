import json

file_path = "temp/temp.json"

def validation_func(file_path):
    error_list = []
    unique_uuids = set()
    unique_cads = set()
    unique_codes_community = set()
    unique_codes_residence = set()
    
    def code_uniqueness(codes, code_set):
        for i in codes:
            code = i["code"]
            if code not in code_set:
                code_set.add(code)
            elif not(len(code) <= 8 and len(code) >= 7):
                error_list.append(
                    f"In index {idx} this code {code} is too long"
                )
            else:
                error_list.append(
                    f"In index {idx} this code {code} is duplicate"
                )
    

    with open(file_path, "r") as read_file:
        object = json.load(read_file)
        data = object["data"]
        for idx, item in enumerate(data):
            unit_names = item["unit_names"]
            classifier_codes = item["classifier_codes"]
            parent_units = item["parent_units"]

            uuid = item["uuid"]
            cad_code = item["cadastral_code"]
            type_id = item["type_id"]

            if type_id != "region":
                last_parrent_units = parent_units[-1]
            if uuid not in unique_uuids:
                unique_uuids.add(uuid)
            else:
                error_list.append(f"In index {idx} this \
                                  uuid {uuid} is duplicate"
                )


            if type_id == "community":
                if cad_code != "":
                    error_list.append(f"In index {idx} cadastral\
                                       code should not exist"
                    )
                code_uniqueness(classifier_codes, unique_codes_community)

                
            elif type_id == "residence":
                if cad_code == "":
                    error_list.append(
                        f"In index {idx} the cadastral\
                            code for this {uuid} is missing"
                    )
                else:
                    if cad_code not in unique_cads:
                        unique_cads.add(cad_code)
                    else:
                        if cad_code!= "---":
                            error_list.append(
                                f"In index {idx} this cadastral code\
                                {cad_code} for this uuid {uuid} is duplicate"
                            )
                code_uniqueness(classifier_codes,unique_codes_residence)

            try:
                if type_id != "region":
                    if last_parrent_units["end_date"] != "":
                        check_unit_names = item["unit_names"]
                        check_class_codes = item["classifier_codes"]

                        if check_unit_names[-1]['end_date'] == ""\
                              or check_class_codes[-1]['end_date'] == "":
                            error_list.append(
                                f"In index {idx} parrent uuid {parrent_uuid}\
                                has end date but unit names and\
                                classifier codes don't"
                            )
            except Exception as ex:
                error_list.append(f"In index {idx} the exception {ex}")


            try:
                for unit in unit_names + classifier_codes + parent_units:
                    start_date = unit["start_date"]
                    end_date = unit["end_date"]
                    if start_date and end_date and start_date > end_date:
                        error_list.append(
                            f"In index {idx} wrong position\
                                  of dates for uuid {uuid}"
                        )
            except Exception as ex:
                error_list.append(f"In index {idx} wrong position\
                                   of dates for uuid {uuid}"
                )
            

            try:
                for p1 in parent_units:
                    parrent_uuid = p1["parent_uuid"]
                    if parrent_uuid not in unique_uuids:
                        error_list.append(
                            f"In index {idx} parrent uuid\
                                  {parrent_uuid} missing for the uuid {uuid}"
                        )
            except Exception as ex:
                error_list.append(
                    f"In index {idx} parrent uuid\
                          {parrent_uuid} missing for the uuid {uuid}"
                )
    
    return error_list


    