package multiship_v1;

import java.io.IOException;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map.Entry;
import java.util.TreeSet;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.net.ssl.HttpsURLConnection;

/**
 * Non Official MultiShip Integration Toolkit
 * 
 * @author ah
 */

public class MultiShip {
    
    /**
     * Returns result of execution request to MultiSHip API
     * sent to api_url with previously signed with secure_key
     * data upload.
     * <p>
     * !IMPORTANT! data mustn't contain secure_key field,
     * because of it will be generated avtomatically by build_query
     * subrequest.
     * 
     * @param api_url MultiShip API URL finished with method name
     * @param data request data must be sent to MultiShip
     * @param secure_key secure key for specified method obtained from MultiShip
     * @return
     * @throws MalformedURLException if URL missformed
     * @throws IOException if some connection problem performed
     * @throws NoSuchAlgorithmException if can't calculate md5 hash
     */
    
    public static JsonObject request(String api_url, JsonObject data, String secure_key) throws MalformedURLException, IOException, NoSuchAlgorithmException
    {      
        HttpsURLConnection loader;
        JsonReader reader;
        JsonObject answer;
        
        loader = (HttpsURLConnection) new URL(api_url).openConnection();
        loader.setRequestMethod("POST");
        loader.setDoOutput(true);
        loader.setReadTimeout(10000);
        
        loader.getOutputStream().write(MultiShip.build_query(data, secure_key).getBytes("UTF-8"));
        
        loader.connect();

        reader = Json.createReader(loader.getInputStream());
        answer = reader.readObject();
        
        loader.disconnect();
        reader.close();
                
        return answer;
    }
        
    /**
     * Returns well-formed signed POST-data for MultiShip API request
     * Obtains JSON formed object with MultiShip request 
     * and secure_key received from MultiSHip used for sign
     * 
     * @param data upload for MultiShip API request
     * @param key secure key received from MultiShip
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String build_query(JsonValue data, String key) throws NoSuchAlgorithmException
    {
        MessageDigest md5_provider;
        BigInteger md5_hash;
        String secret_key;
        
        TreeSet<String> set = new TreeSet<>();
        StringBuilder to_sign = new StringBuilder();
        
        String result = MultiShip._build_query(data, "");
        
        // Sign Query
        set.addAll(Arrays.asList(result.split("&")));

        for(String var : set)
        {
            String[] arg = var.split("=",2);
            to_sign.append(arg[1]);
        }
        
        to_sign.append(key);

        md5_provider = MessageDigest.getInstance("MD5");
        md5_hash = new BigInteger(1, md5_provider.digest(to_sign.toString().getBytes()));
        secret_key = md5_hash.toString(16);
 
        return result.substring(0, result.length() - 1).concat("&secret_key=").concat(secret_key);
    }
        
    private static String _build_query(JsonValue data, String prefix)
    {
        StringBuilder result = new StringBuilder();
        
        switch(data.getValueType())
        {
            case ARRAY:
            {
                for (int i = 0; i < ((JsonArray)data).size(); i++)
                {
                    result.append(MultiShip._build_query(((JsonArray)data).get(i), prefix + "[" + i + "]"));
                }
                break;
            }
            default:
            {
                for(Entry<String, JsonValue> record : ((JsonObject)data).entrySet())
                {
                    if(record.getValue().getValueType() != JsonValue.ValueType.ARRAY)
                    {
                        if(prefix.isEmpty())
                            result.append(record).append("&");
                        else
                            result.append(prefix).append("[").append(record.getKey()).append("]=").append(record.getValue()).append("&");
                    }
                    else
                    {
                        if(prefix.isEmpty())
                            result.append(MultiShip._build_query((JsonValue)record.getValue(), record.getKey()));
                        else
                            result.append(MultiShip._build_query((JsonValue)record.getValue(), prefix + "[" + record.getKey() + "]"));
                    }
                }
            }
        }
        
        return result.toString();
    }
}