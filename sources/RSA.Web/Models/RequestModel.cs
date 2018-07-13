using RSA.Web.Helpers;
using System.Runtime.Serialization;

namespace RSA.Web.Models
{
    /// <summary>
    /// 加密请求基类
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class RequestBaseModel<T>
    {
        /// <summary>
        /// 真实数据包
        /// </summary>
        public T Data { get; set; }

        /// <summary>
        /// 反序列化用数据
        /// </summary>
        public object data { set { InitData(value.ToString()); } }

        private void InitData(string value)
        {
            Data = JsonHelper.DeserializeObject<T>(value);
        }
    }

    [DataContract]
    public class ResCryptTestModel
    {
        [DataMember(Name = "login_account")]
        public string Account { get; set; }

        [DataMember(Name = "login_password")]
        public string Password { get; set; }

        [DataMember(Name = "detail")]
        public DetailModel DetailData { get; set; }

    }

    [DataContract]
    public class DetailModel
    {
        [DataMember(Name = "flag")]
        public int Flag { get; set; }
    }

    public class ResultModel
    {
        public string code { get; set; } = "000";
        public string message { get; set; } = "success";
        public object data { get; set; }
    }
}