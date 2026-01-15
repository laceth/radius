## PREREQUISITES - CODEOWNERS Configuration

A default CODEOWNERS file has been added to this repository. By default, it may include all users with write access, which can result in unnecessary review notifications for large teams.

### Why Update the CODEOWNERS File?

Updating the CODEOWNERS file ensures that only the relevant team members are assigned as reviewers for pull requests. This helps:
- Reduce notification noise
- Improve review efficiency
- Maintain clear ownership of code changes

### How to Customize

1. Open the `.github/CODEOWNERS` file in your repository.
2. Replace the default entry with specific paths and team members or GitHub usernames.

**Example:**
# Set code owners for all files
```
* @Forescout/TEAM_NAME
```  

# Set code owners for specific directories
```
/docs/ @Forescout/doc-team 
/src/  @Forescout/backend-team
/scripts/ @USER
```  

For more details, refer to GitHub [CODEOWNERS documentation](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)
