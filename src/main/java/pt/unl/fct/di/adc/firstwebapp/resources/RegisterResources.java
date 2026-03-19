package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.appengine.repackaged.org.apache.commons.codec.digest.DigestUtils;
import com.google.gson.Gson;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;

import pt.unl.fct.di.adc.firstwebapp.util.LoginData;

import java.util.logging.Logger;

@Path("/register")
public class RegisterResources {

    /// copied from other classes
    /// tool that prints messages in the terminal (like System.out.println), every message printed will have a "tag" of RegisterResources
    /// it allow us to know where possible error are, in what class they're in
    private static final Logger LOG = Logger.getLogger(RegisterResources.class.getName());

    /// converts an object of java to json format or vice versa
    private final Gson g = new Gson();

    /// connects the application to a database in Google Cloud
    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public RegisterResources() {}

    @POST
    @Path("/v1")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response registerUser(LoginData data) {
        /// writes a message
        LOG.fine("Registering user: " + data.username);

        /// creates a key for the kind "User" and the ID is the username
        Key key = datastore.newKeyFactory().setKind("User").newKey(data.username);

        /// creates an entity with the key above and sets/creates the properties (user_password and timestamp: time of creation)
        /// set("user_pwd",  data.password): it works, but is recommended not to use the actual password
        /// if our database is breached by a hacker, he as access to the actual password of the user, so, we have to protect it
        ///  DigestUtils.sha512Hex(data.password) does the safety technique called hashing
        Entity user = Entity.newBuilder(key).set("user_pwd", DigestUtils.sha512Hex(data.password)).set("user_time", Timestamp.now()).build();

        /// datastore.add(user): adds user in the database (gives an error if exists a same key)
        /// adds or updates a user in the database (replaces old data for the new one)
        datastore.put(user);

        LOG.fine("User: " + data.username + " registered");

        /// system returns an HTTP 200 ok state, entity is the body of the message (data that you want to send to client)
        return Response.ok().entity(g.toJson(true)).build();
    }


    /// did by GEMINI, test if user is actually saved locally after the POST command in postman
    /// to use the environment variables temporarily in windows (to be permanent, I have to use variable systems in settings):
    /**
     * Emulators are like a clone of our Google database in our local computer, so, to not use the deployed application and test it in the localhost, we have to do this:
     * one window:
     * gcloud beta emulators datastore start
     * other window:
     * set DATASTORE_USE_PROJECT_ID_AS_APP_ID=true
     * set DATASTORE_DATASET=sigma-nimbus-489218
     * set DATASTORE_EMULATOR_HOST=localhost:8081
     * set DATASTORE_EMULATOR_HOST_PATH=localhost:8081/datastore
     * set DATASTORE_HOST=http://localhost:8081
     * set DATASTORE_PROJECT_ID=sigma-nimbus-489218
     */

    @GET
    @Path("/{username}")
    public Response checkUser(@PathParam("username") String username) {
        LOG.fine("A verificar se o utilizador existe: " + username);

        // 1. Cria a chave de pesquisa com o nome que enviarmos no URL
        Key key = datastore.newKeyFactory().setKind("User").newKey(username);

        // 2. Vai à base de dados procurar essa chave
        Entity user = datastore.get(key);

        // 3. Verifica se encontrou alguma coisa
        if (user != null) {
            // Sucesso! Vamos extrair o Hash para você ver que funcionou
            String hashGuardado = user.getString("user_pwd");
            return Response.ok().entity(g.toJson("O utilizador " + username + " existe! Hash da password: " + hashGuardado)).build();
        } else {
            // Não encontrou ninguém com esse nome
            return Response.status(404).entity(g.toJson("Erro: Utilizador não existe na base de dados.")).build();
        }
    }
}
