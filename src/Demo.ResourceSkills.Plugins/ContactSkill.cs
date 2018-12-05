using Microsoft.Xrm.Sdk;
using Microsoft.Xrm.Sdk.Query;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel;
using System.Text;
using System.Threading.Tasks;

namespace Demo.ResourceSkills.Plugins
{
    public class ContactSkill : IPlugin
    {
        public void Execute(IServiceProvider serviceProvider)
        {
            // Extract the tracing service for use in debugging sandboxed plug-ins.  
            // If you are not registering the plug-in in the sandbox, then you do  
            // not have to add any tracing service related code.  
            ITracingService tracingService = (ITracingService)serviceProvider.GetService(typeof(ITracingService));

            // Obtain the execution context from the service provider.  
            IPluginExecutionContext context = (IPluginExecutionContext)serviceProvider.GetService(typeof(IPluginExecutionContext));

            // The InputParameters collection contains all the data passed in the message request.  
            if (context.InputParameters.Contains("Target") && context.InputParameters["Target"] is Entity)
            {
                // Obtain the target entity from the input parameters.  
                Entity entity = (Entity)context.InputParameters["Target"];

                // Verify that the target entity represents an entity type you are expecting.   
                // For example, an account. If not, the plug-in was not registered correctly.  
                if (entity.LogicalName != "demo_contactskill")
                    return;

                // Obtain the organization service reference which you will need for  
                // web service calls.  
                IOrganizationServiceFactory serviceFactory = (IOrganizationServiceFactory)serviceProvider.GetService(typeof(IOrganizationServiceFactory));
                IOrganizationService service = serviceFactory.CreateOrganizationService(context.UserId);

                try
                {
                    var contactId = (EntityReference)entity.Attributes["demo_contactid"];
                    var skillId = (EntityReference)entity.Attributes["demo_resourceskillid"];

                    var fetchxml = $@"<fetch version='1.0' output-format='xml-platform' mapping='logical' distinct='false'>
                                      <entity name='demo_contactskill'>
                                        <filter type='and'>
                                          <condition attribute='demo_contactid' operator='eq' value='{contactId.Id}' />
                                          <condition attribute='demo_resourceskillid' operator='eq' value='{skillId.Id}' />
                                        </filter>
                                      </entity>
                                    </fetch>";

                    tracingService.Trace("FetchXML: {0}", fetchxml);

                    var result = service.RetrieveMultiple(new FetchExpression(fetchxml));

                    tracingService.Trace("Result count: {0}", result.Entities.Count());

                    if (result.Entities.Any())
                    {
                        throw new InvalidPluginExecutionException("Skill rating for this contact and resource skill already exists.  ");
                    }
                        
                }

                catch (FaultException<OrganizationServiceFault> ex)
                {
                    throw new InvalidPluginExecutionException("An error occurred in ContactSkill Plugin.", ex);
                }

                catch (Exception ex)
                {
                    tracingService.Trace("ContactSkill Exception: {0}", ex.ToString());
                    throw;
                }
            }
        }
    }
}
