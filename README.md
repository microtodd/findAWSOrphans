# findAWSOrphans
Find running AWS resources not tied to a CF stack

When run, will examine all your running resources and compare to your CF stacks.  Any running resources not tied to a CF stack are identified.


    findOrphans.py

    Required:
    -e <arn>        ARN of role to run as
    -p <name>       Profile name to run as
    -r <region>     Region

    Optional:
    -h              print help and exit
    -v              verbose mode
    -l              check ELBs
    -s              check SGs
    -i              check EIPs
    -n              check ENIs
    -c              check Instances
    -a              check All
