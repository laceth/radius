## Pull Request Checklist

Before you open this PR, double-check the following things:
    
1. The fix information is available in the JIRA ticket.
2. The dev test environment details are available in the JIRA Ticket. i.e.: CA version, Plugin version, switches used.
3. Lack of fix information or dev test environment details will lead to the assumption that the ticket is not tested and lead to rejection.
4. You are merging onto the correct branch (is it a release? hotfix? master?).
5. Delete this and the title section of this template before submitting.


## Title:
The title for your PR should follow the following format, if you shorten the ticket name, it must contain the key points of the original title, otherwise it needs to be copied exactly. 

<YOUR_JIRA_PROJECT_KEY>-####: Original name of ticket 

Example: ABCD-0123: Your Ticket Summary or Title

### Problem:

The problem description should go here.

What was the original ticket created for? If a defect, state what was wrong, if a feature request, state what was being added functionality wise. 

### Solution:

The solution text should go here.

This section needs to cover what you are changing in the code, if it is a small number of code changes, give a high level explanation of these changes that anyone who reads the PR should be able to follow. If lots of changes are in the ticket, then give a high level summary of the changes for the ticket. 
What you did and why you did it are key.