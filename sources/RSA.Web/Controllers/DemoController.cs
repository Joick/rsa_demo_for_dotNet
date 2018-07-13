using RSA.Web.Attributes;
using RSA.Web.Helpers;
using RSA.Web.Models;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace RSA.Web.Controllers
{
    public class DemoController : ApiController
    {
        [HttpPost]
        [DecryptHandler("EncryptTest")]
        public HttpResponseMessage DoDecryptNReturn(RequestBaseModel<ResCryptTestModel> reqModel)
        {
            return Request.CreateResponse(HttpStatusCode.OK, reqModel);
        }

        [HttpGet]
        public HttpResponseMessage QueryRsaPublicKey()
        {
            ResultModel result = new ResultModel();

            result.data = RSAHelper.GetPublicKey();

            return Request.CreateResponse(HttpStatusCode.OK, result);
        }
    }
}