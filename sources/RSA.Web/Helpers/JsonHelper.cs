using Newtonsoft.Json;

namespace RSA.Web.Helpers
{
    /// <summary>
    /// Json帮助类
    /// </summary>
    public static class JsonHelper
    {
        /// <summary>
        /// Json转换成对象
        /// </summary>
        /// <param name="dt"></param>
        /// <returns></returns>
        public static object Deserialize(string data)
        {
            return JsonConvert.DeserializeObject(data);
        }

        /// <summary>
        /// 把对象转成json字符串
        /// </summary>
        /// <param name="o">对象</param>
        /// <returns>json字符串</returns>
        public static string Serialize(object o)
        {
            return JsonConvert.SerializeObject(o);
        }

        /// <summary>
        /// 反序列化
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data">json字符串</param>
        /// <returns></returns>
        public static T DeserializeObject<T>(string data)
        {
            return JsonConvert.DeserializeObject<T>(data);
        }

        /// <summary>
        /// 序列化
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="obj">序列化对象</param>
        /// <returns></returns>
        public static string SerializeObject<T>(T obj)
        {
            return JsonConvert.SerializeObject(obj);
        }
    }
}