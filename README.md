Instructions on how to work with the script:

- Create a read/write token in your Black Duck instance and keep it handy.
- Install requirements using the command mentioned below. 
- Follow the DOC instructions using the --help command on the script 

Use the requirements file to install dependencies using:
- pip install -r requirements.txt

What can the script do right now? 

- Goes through the BOM
- Identifies CentOS/ RedHat Origins
- Queries Redhat, checks for "Not Affected" origins
- If things are not affected, marks them as "Ignored" on the BOM

Sample Command:
python3 vuln_ignore.py --instance <host> --token <token_from_bd> --project <project_uuid_on_bd> --version <version_uuid_on_bd>