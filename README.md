# PowerApps CDS DevOps Template
This project can server as a template to teams taking on PowerApps that manages the source code of any customizations through the CDS solution system and record data files.

## Goals of the Project
This project aims to achieve developer isolation for team development of CDS based solutions and fully automate build and release management with Azure DevOps Pipelines.

Presentation, "ALM Practices for Building Common Data Service Products and Services", that accompanies this project can be found in the /docs folder.

Example build for the project can be found in the /deploy folder with a Build Pipeline YAML definition.  The build definition includes the use of The D365 Build Tools for solution packaging and VSTS-debugging extension to assist with debugging efforts.

## Open Source Projects Utilized

**Dynamics 365 Build Tools** by Wael Hamze  
https://marketplace.visualstudio.com/items?itemName=WaelHamze.xrm-ci-framework-build-tasks  
https://github.com/WaelHamze/dyn365-ce-vsts-tasks  
https://waelhamze.wordpress.com/  

**Adoxio.Dynamics.DevOps** by Alan Mervitz  
https://github.com/Adoxio/Adoxio.Dynamics.DevOps  
https://alanmervitz.com  

**Microsoft.Xrm.Data.PowerShell** by Sean McNellis & Kenichiro Nakamura  
https://github.com/seanmcne/Microsoft.Xrm.Data.PowerShell  

**VSTS Build/Release Tasks for debugging pipelines** by Max K. (knom)   
https://marketplace.visualstudio.com/items?itemName=knom.vsts-debughelper-tasks  
https://github.com/knom/vsts-debug-tasks/  

## Comments

Note that the script "Base" and "Skills" import/export settings are the working examples in this project.  Request and Full setting configurations are for demonstration purposes only.
