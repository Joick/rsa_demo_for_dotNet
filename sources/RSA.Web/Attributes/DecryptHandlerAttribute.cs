using RSA.Web.Helpers;
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Web.Http.Controllers;
using System.Web.Http.Filters;

namespace RSA.Web.Attributes
{
    public class DecryptHandlerAttribute : ActionFilterAttribute
    {
        private static string serviceType = string.Empty;

        public DecryptHandlerAttribute(string type)
        {
            serviceType = type;
        }

        public override void OnActionExecuting(HttpActionContext actionContext)
        {
            try
            {
                Stream stream = actionContext.Request.Content.ReadAsStreamAsync().Result;
                Encoding encoding = Encoding.UTF8;

                stream.Position = 0;
                string responseData = "";

                using (StreamReader reader = new StreamReader(stream, encoding))
                {
                    responseData = reader.ReadToEnd().ToString();
                }

                var realData = string.Empty;

                try
                {
                    realData = RSAHelper.Decrypt(responseData);
                }
                catch
                {
                    actionContext.Response = actionContext.Request.CreateErrorResponse(HttpStatusCode.BadRequest, "请求数据异常。");
                    return;
                }

                foreach (var argument in actionContext.ActionArguments)
                {
                    Type type = argument.Value.GetType();
                    PropertyInfo[] ps = type.GetProperties();

                    foreach (PropertyInfo i in ps)
                    {
                        string name = i.Name;

                        if (name == "data")
                        {
                            i.SetValue(argument.Value, realData);
                            break;
                        }

                    }
                }
            }
            catch
            {
                actionContext.Response = actionContext.Request.CreateErrorResponse(HttpStatusCode.Unauthorized, "服务授权信息校验异常。");
            }
        }
    }
}