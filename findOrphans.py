#
# Compare running resources to the CF stacks, determine if anything is "orphaned".
#
import boto3
import sys
import getopt

###
def printHelp():
    print '''
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
    '''

###
def checkELBs(stsCreds,stackELBs,verbose=False,region='us-east-1'):

    # Local
    unmatchedELBs = []

    # Get list of running ELBs
    elbClient = boto3.client('elb',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)

    nextToken = 1
    while nextToken is not None:
        runningELBs = None
        if nextToken == 1:
            runningELBs = elbClient.describe_load_balancers()
        else:
            runningELBs = elbClient.describe_load_balancers(Marker=nextToken)
        nextToken = runningELBs.get('NextMarker')
    
        # Find unmatched
        for runningELB in runningELBs['LoadBalancerDescriptions']:
            if verbose:
                print 'runningELB => ' + runningELB['LoadBalancerName']
            if runningELB['LoadBalancerName'] not in stackELBs:
                unmatchedELBs.append(runningELB['LoadBalancerName'])

    # report
    for unmatchedELB in unmatchedELBs:
        print 'unmatchedELB => ' + unmatchedELB

    return unmatchedELBs

###
def checkSGs(stsCreds,stackSGs,verbose=False,region='us-east-1'):

    # Local
    unmatchedSGs = []

    # Get list of SGs in the environment
    sgClient = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningSGs = sgClient.describe_security_groups()

    # Find unmatched
    for runningSG in runningSGs['SecurityGroups']:
        if verbose:
            print 'runningSG => ' + runningSG['GroupId']
        if runningSG['GroupId'] not in stackSGs:
            unmatchedSGs.append(runningSG['GroupId'] + ' (' + runningSG['GroupName'] + ')')
    for sg in unmatchedSGs:
        print 'unmatchedSG => ' + sg

    return unmatchedSGs

###
def checkEIPs(stsCreds,stackEIPs,verbose=False,region='us-east-1'):

    # Local
    unmatchedEIPs = []

    # Get list of EIPs in the environment
    sgClient = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningEIPs = sgClient.describe_addresses()

    # Find unmatched
    for running in runningEIPs['Addresses']:
        if verbose:
            print 'runningEIP => ' + running['PublicIp']
        if running['PublicIp'] not in stackEIPs:
            unmatchedEIPs.append(running['PublicIp'])
    for addr in unmatchedEIPs:
        print 'unmatchedEIPs => ' + addr

    return unmatchedEIPs

###
def checkENIs(stsCreds,stackENIs,verbose=False,region='us-east-1'):

    # Local
    unmatchedENIs = {}

    # Get list of ENIs in the environment
    client = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    runningENIs = client.describe_network_interfaces()

    # Find unmatched
    for running in runningENIs['NetworkInterfaces']:

        # Skip abstract service ENIs
        if running.get('Attachment') and 'amazon' in running.get('Attachment').get('InstanceOwnerId'):
            continue

        if verbose:
            print 'runningENI => ' + str(running.get('NetworkInterfaceId'))

        # Finding whether this ENI is 'valid' is complicated.
        # A: See if ENI in stackENIs.  If so, valid.
        # B: See if ENI is attached to a stack instance.  If so, valid.
        # We handled this by making suring the list of stackENIs we got included
        # both types.
        #
        if running['NetworkInterfaceId'] not in stackENIs:
            attachedInstance = 'unattached'
            if running.get('Attachment') and running['Attachment'].get('InstanceId'):
                attachedInstance = running['Attachment']['InstanceId']
            unmatchedENIs[running['NetworkInterfaceId']] = running.get('Description','NameUnknown') + '/' + running.get('PrivateIpAddress','IPUnknown') + '/' + attachedInstance

    for interface in unmatchedENIs:
        print 'unmatchedENIs => ' + interface + ' (' + unmatchedENIs[interface] + ')'

    return unmatchedENIs.keys()

###
def checkInstances(stsCreds,stackInstances,verbose=False,region='us-east-1'):

    # Local
    unmatchedInstances = {}

    # Get list of all running instances
    client = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    nextToken = 1
    while nextToken is not None:
        runningInstances = None
        if nextToken == 1:
            runningInstances = client.describe_instances()
        else:
            runningInstances = client.describe_instances(NextToken=nextToken)
        nextToken = runningInstances.get('NextToken')

        for r in runningInstances['Reservations']:
            for i in r['Instances']:

                # Only look at active instances
                if i['State']['Name'] == 'terminated' or i['State']['Name'] == 'shutting-down':
                    continue

                if verbose:
                    print 'runningInstance => ' + i['InstanceId']

                if i['InstanceId'] not in stackInstances:
                    instanceName = 'unknown'
                    for tag in i['Tags']:
                        if tag['Key'] == 'Name':
                            instanceName = tag['Value']
                    unmatchedInstances[i['InstanceId']] = instanceName

    # report
    for i in unmatchedInstances:
        print 'unmatchedInstance => ' + i + ' (' + unmatchedInstances[i] + ')'

    return unmatchedInstances.keys()

###
def getAllInstanceENIs(stsCreds,stackInstances,verbose=False,region='us-east-1'):
    instanceIDs = {}
    client = boto3.client('ec2',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=region)
    nextToken = 1
    while nextToken is not None:
        runningInstances = None
        if nextToken == 1:
            runningInstances = client.describe_instances()
        else:
            runningInstances = client.describe_instances(NextToken=nextToken)
        nextToken = runningInstances.get('NextToken')

        for r in runningInstances['Reservations']:
            for i in r['Instances']:

                # Only look at stack instances
                if i['InstanceId'] not in stackInstances:
                    continue

                # Only look at active instances
                if i['State']['Name'] == 'terminated' or i['State']['Name'] == 'shutting-down':
                    continue

                # Find all ENIs on this instance
                for ifs in i['NetworkInterfaces']:
                    instanceIDs[ifs['NetworkInterfaceId']] = stackInstances.get(i['InstanceId'],'Unknown')
                    if verbose:
                        print 'stackeni => ' + ifs['NetworkInterfaceId'] + ' => ' + stackInstances.get(i['InstanceId'],'Unknown')

    return instanceIDs

###
def main(argv):

    # Session
    ARN = None
    Profile = None
    Verbose = False
    CheckELBs = False
    CheckSGs = False
    CheckEIPs = False
    CheckENIs = False
    CheckInstances = False
    Region = 'us-east-1'

    # Parse CL opts
    opts, args = getopt.getopt(argv,'hvlsaince:p:r:')
    for opt, arg in opts:
        if opt == '-h':
            printHelp()
            sys.exit(0)
        if opt == '-e':
            ARN = str(arg)
        if opt == '-p':
            Profile = str(arg)
        if opt == '-r':
            Region = str(arg)
        if opt == '-v':
            Verbose = True
        if opt == '-l':
            CheckELBs = True
        if opt == '-s':
            CheckSGs = True
        if opt == '-i':
            CheckEIPs = True
        if opt == '-n':
            CheckENIs = True
        if opt == '-c':
            CheckInstances = True
        if opt == '-a':
            CheckELBs = True
            CheckSGs = True
            CheckEIPs = True
            CheckENIs = True
            CheckInstances = True

    # Validate
    if ARN == None or Profile == None:
        print 'Error: Must specify environment with -e and profile with -p'
        sys.exit(-1)

    # Get applicable creds
    mySession = boto3.Session(profile_name=Profile)
    stsClient = mySession.client('sts')
    stsCreds = stsClient.assume_role(RoleArn=ARN,RoleSessionName='thisSession')
    stsCreds = stsCreds['Credentials']

    # Get all running stacks/resources
    stackELBs = {} # AWS::ElasticLoadBalancing::LoadBalancer
    stackInstances = {} # AWS::AutoScaling::AutoScalingGroup,AWS::EC2::Instance
    stackSGs = {} # AWS::EC2::SecurityGroup
    stackEIPs = {} # AWS::EC2::EIP
    stackENIs = {} # AWS::EC2::NetworkInterface
    stackResourceTypes = {}
    cfClient = boto3.client('cloudformation',
        aws_access_key_id=stsCreds['AccessKeyId'],
        aws_secret_access_key=stsCreds['SecretAccessKey'],
        aws_session_token=stsCreds['SessionToken'],
        region_name=Region)

    # Some of the API calls only give you a paginated return list
    nextToken = 1
    while nextToken is not None:
        allRunningStacks = None
        if nextToken == 1:
            allRunningStacks = cfClient.list_stacks(StackStatusFilter=['CREATE_COMPLETE','UPDATE_COMPLETE'])
        else:
            allRunningStacks = cfClient.list_stacks(StackStatusFilter=['CREATE_COMPLETE','UPDATE_COMPLETE'],NextToken=nextToken)
        nextToken = allRunningStacks.get('NextToken')

        # Iterate stacks in this pull
        for stack in allRunningStacks['StackSummaries']:
            nextStackToken = 1
            while nextStackToken is not None:
                thisStackResources = None
                if nextStackToken == 1:
                    thisStackResources = cfClient.list_stack_resources(StackName=stack['StackName'])
                else:
                    thisStackResources = cfClient.list_stack_resources(StackName=stack['StackName'],NextToken=nextStackToken)
                nextStackToken = thisStackResources.get('NextToken')
    
                for resource in thisStackResources['StackResourceSummaries']:
                    stackResourceTypes[resource['ResourceType']] = 1
    
                    # Only check running resources
                    if resource['ResourceStatus'] != 'CREATE_COMPLETE' and resource['ResourceStatus'] != 'UPDATE_COMPLETE':
                        continue
    
                    # ELBs
                    if resource['ResourceType'] == 'AWS::ElasticLoadBalancing::LoadBalancer' and CheckELBs:
    
                        if Verbose:
                            print 'stackelb => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                        stackELBs[resource['PhysicalResourceId']] = stack['StackName']
    
                    # Security Groups
                    elif resource['ResourceType'] == 'AWS::EC2::SecurityGroup' and CheckSGs:
                        if Verbose:
                            print 'stacksg => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                        stackSGs[resource['PhysicalResourceId']] = stack['StackName']

                    # Elastic IPs
                    elif resource['ResourceType'] == 'AWS::EC2::EIP' and CheckEIPs:
                        if Verbose:
                            print 'stackeip => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                        stackEIPs[resource['PhysicalResourceId']] = stack['StackName']

                    # ENIs
                    elif resource['ResourceType'] == 'AWS::EC2::NetworkInterface' and CheckENIs:
                        if Verbose:
                            print 'stackeni => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                        stackENIs[resource['PhysicalResourceId']] = stack['StackName']
    
                    # Instances
                    # We need the instance list for ENI check as well
                    #
                    # See if any actual instances defined
                    elif resource['ResourceType'] == 'AWS::EC2::Instance' and (CheckInstances or CheckENIs):
                        if Verbose and CheckInstances:
                            print 'stackinstance => ' + resource['PhysicalResourceId'] + ' => ' + stack['StackName']
                        stackInstances[resource['PhysicalResourceId']] = stack['StackName']

                    # Instances
                    #
                    # Check ASGs
                    elif resource['ResourceType'] == 'AWS::AutoScaling::AutoScalingGroup' and (CheckInstances or CheckENIs):
                        thisASGName = resource['PhysicalResourceId']
                        # Enumerate the ASGs and find all running attached instances
                        asgClient = boto3.client('autoscaling',
                            aws_access_key_id=stsCreds['AccessKeyId'],
                            aws_secret_access_key=stsCreds['SecretAccessKey'],
                            aws_session_token=stsCreds['SessionToken'],
                            region_name=Region)
                        nextASGToken = 1
                        while nextASGToken is not None:
                            asgs = None
                            if nextASGToken == 1:
                                asgs = asgClient.describe_auto_scaling_groups(AutoScalingGroupNames=[thisASGName])
                            else:
                                asgs = asgClient.describe_auto_scaling_groups(AutoScalingGroupNames=[thisASGName],NextToken=nextASGToken)
                            nextASGToken = asgs.get('NextToken')

                            for asg in asgs['AutoScalingGroups']:
                                for instance in asg['Instances']:
                                    if Verbose and CheckInstances:
                                        print 'stackinstance => ' + instance['InstanceId'] + ' (asg ' + thisASGName + ') => ' + stack['StackName']
                                    stackInstances[instance['InstanceId']] = stack['StackName']

    
    # Do ELBs
    unmatchedELBs = None
    if CheckELBs:
        unmatchedELBs = checkELBs(stsCreds,stackELBs,verbose=Verbose,region=Region)
    
    # DO SGs
    unmatchedSGs = None
    if CheckSGs:
        unmatchedSGs = checkSGs(stsCreds,stackSGs,verbose=Verbose,region=Region)

    # Do EIPs
    unmatchedEIPs = None
    if CheckEIPs:
        unmatchedEIPs = checkEIPs(stsCreds,stackEIPs,verbose=Verbose,region=Region)

    # Do ENIs
    unmatchedENIs = None
    if CheckENIs:

        # Need to also check ENIs tied to all instances
        moreStackENIs = getAllInstanceENIs(stsCreds,stackInstances,verbose=Verbose,region=Region)

        # do check
        stackENIs.update(moreStackENIs)
        unmatchedENIs = checkENIs(stsCreds,stackENIs,verbose=Verbose,region=Region)

    # Do instances
    unmatchedInstances = None
    if CheckInstances:
        unmatchedInstances = checkInstances(stsCreds,stackInstances,verbose=Verbose,region=Region)

###
if __name__ == '__main__':
    main(sys.argv[1:])

