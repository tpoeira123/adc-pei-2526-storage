package pt.unl.fct.di.adc.firstwebapp.resources;

import java.util.Date;
import java.util.List;
import java.util.Calendar;
import java.util.ArrayList;
import java.util.logging.Logger;

import java.util.Date;
import java.util.List;
import java.util.Calendar;
import java.util.ArrayList;
import java.util.logging.Logger;

import com.google.cloud.datastore.*;
import org.apache.commons.codec.digest.DigestUtils;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response.Status;

import jakarta.servlet.http.HttpServletRequest;

import pt.unl.fct.di.adc.firstwebapp.util.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.util.LoginData;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.StructuredQuery.OrderBy;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;

import com.google.gson.Gson;


@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	private static final String MESSAGE_INVALID_CREDENTIALS = "Incorrect username or password.";
	private static final String MESSAGE_NEXT_PARAMETER_INVALID = "Request parameter 'next' must be greater or equal to 0.";


	private static final String LOG_MESSAGE_LOGIN_ATTEMP = "Login attempt by user: ";
	private static final String LOG_MESSAGE_LOGIN_SUCCESSFUL = "Login successful by user: ";
	private static final String LOG_MESSAGE_WRONG_PASSWORD = "Wrong password for: ";
	private static final String LOG_MESSAGE_UNKNOW_USER = "Failed login attempt for username: ";

	private static final String USER_PWD = "user_pwd";
	private static final String USER_LOGIN_TIME = "user_login_time";

	/** 
	 * Logger Object
	 */
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	private static final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	private static final KeyFactory userKeyFactory = datastore.newKeyFactory().setKind("User");

	private final Gson g = new Gson();

	public LoginResource() {} // Nothing to be done here
	
	@POST
	@Path("/")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		if(data.username.equals("user") && data.password.equals("password")) {
			AuthToken at = new AuthToken(data.username);
			return Response.ok(g.toJson(at)).build();
		}

		return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		
	}
	
	@GET
	@Path("/{username}")
	public Response checkUsernameAvailable(@PathParam("username") String username) {
		if(username.trim().equals("user")) {
			return Response.ok().entity(g.toJson(false)).build();
		} else {
			return Response.ok().entity(g.toJson(true)).build();
		}
	}

	// task3
	@POST
	@Path("/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLoginV1(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = userKeyFactory.newKey(data.username);
		Entity user = datastore.get(userKey);

		if(user != null) {
			String hashedPWD = user.getString("user_pwd");
			if(hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				LOG.info("User '" + data.username + "' logged in successfully.");

				/// create's a token if pwd given is equal to pwd of user
				/// Security: Your password is only answered by the network once
				/// Validity: Tokens generally have an expiration date (e.g., they expire in 2 hours)
				/// If a hacker steals your token, they only have 2 hours to use it. If they stole the password, they would have access forever
				/// Performance: It is much faster for the server to validate a token's than to go to the database, read passwords or perform cryptographic calculations.
				AuthToken at = new AuthToken(data.username);
				return Response.ok(g.toJson(at)).build();
			}
			else {
				LOG.warning("User '" + data.username + "' provided wrong password.");
				return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
			}
		}
		else {
			LOG.warning("User '" + data.username + "' does not exist.");
			return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		}
	}

	// task3
	@POST
	@Path("/v1a")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLoginV1a(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
		Entity user = datastore.get(userKey);

		if(user != null) {
			String hashedPWD = user.getString("user_pwd");
			if(hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {
				LOG.info("User '" + data.username + "' logged in successfully.");

				/// puts in the database the time this user logged in
				user = Entity.newBuilder(user)
						.set("user_login_time", Timestamp.now())
						.build();

				/// replaces the old user
				datastore.update(user);

				/// creates a token if pwd given is equal to pwd of user
				AuthToken at = new AuthToken(data.username);
				return Response.ok(g.toJson(at)).build();
			}
			else {
				LOG.warning("User '" + data.username + "' provided wrong password.");
				return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
			}
		}
		else {
			LOG.warning("User '" + data.username + "' does not exist.");
			return Response.status(Response.Status.FORBIDDEN).entity("Incorrect username or password.").build();
		}
	}

	// task3
	@POST@Path("/v1b")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLoginV1b(LoginData data) {
		LOG.fine("Attempt to login user: " + data.username);

		Key userKey = userKeyFactory.newKey(data.username);
		Entity user = datastore.get(userKey);

		if( user != null ) {
			String hashedPWD = user.getString("user_pwd");
			if( hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {

				/// Sets a relation father(User) and son (UserLog)
				KeyFactory logKeyFactory = datastore.newKeyFactory()
						.addAncestor(PathElement.of("User", data.username))
						.setKind("UserLog");

				/// A User can have a lot of UserLog, so this basically creates a random unique id for this specific UserLog
				Key logKey = datastore.allocateId(logKeyFactory.newKey());

				/// puts in the database the time this user logged in
				Entity userLog = Entity.newBuilder(logKey)
						.set("user_login_time", Timestamp.now())
						.build();

				/// replaces the old user
				datastore.put(userLog);

				LOG.info("User '" + data.username + "' logged in successfuly.");

				/// creates a token if pwd given is equal to pwd of user
				AuthToken token = new AuthToken(data.username);
				return Response.ok(g.toJson(token)).build();
			}
			else {
				LOG.warning("Wrong password for: " + data.username);
				return Response.status(Status.FORBIDDEN).build();
			}
		}
		else {
			LOG.warning("Failed login attempt for username: " + data.username);
			return Response.status(Status.FORBIDDEN).build();
		}
	}



	// task 4
	@POST
	@Path("/user/v1")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getUserLoginLogsV1(LoginData data) {
		/// Get the date of yesterday ;; Calculate the exact time for 24 hours ago (Yesterday)
		Calendar cal = Calendar.getInstance();

		/// Subtract 1 day from the current date
		cal.add(Calendar.DATE, -1);

		/// Convert it to a Google Cloud Timestamp
		Timestamp yesterday = Timestamp.of(cal.getTime());

		/// Build the Database Query:
		/// We only want to search through "UserLog" entities
		/// CompositeFilter allows us to combine multiple conditions (AND)
		/// Condition A: The log MUST belong to this specific user (The "Parent" folder)
		/// Condition B: The login time MUST be Greater than or Equal (ge) to yesterday
		Query<Entity> query = Query.newEntityQueryBuilder()
				.setKind("UserLog")
				.setFilter(
						CompositeFilter.and(
								StructuredQuery.PropertyFilter.hasAncestor(
										datastore.newKeyFactory().setKind("User").newKey(data.username)),
								PropertyFilter.ge(USER_LOGIN_TIME, yesterday)
						)
				).build();

		/// Execute the query in database and store the results
		QueryResults<Entity> logs = datastore.run(query);

		/// Create an empty list to hold the final dates we want to show the user
		List<Date> loginDates = new ArrayList<>();

		/// Loop through every log the database found
		/// Extract the timestamp, convert it to a standard Java Date, and add it to our list
		logs.forEachRemaining(userlog -> {
			loginDates.add(userlog.getTimestamp(USER_LOGIN_TIME).toDate());
		});
		return Response.ok(g.toJson(loginDates)).build();
	}

	@POST
	@Path("/user/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getLatestLogins(LoginData data) {

		Key userKey = userKeyFactory.newKey(data.username);

		Entity user = datastore.get(userKey);
		if( user != null && user.getString(USER_PWD).equals(DigestUtils.sha512Hex(data.password))) {

			/// Get the date of yesterday ;; Calculate the exact time for 24 hours ago (Yesterday)
			Calendar cal = Calendar.getInstance();

			/// Subtract 1 day from the current date
			cal.add(Calendar.DATE, -1);

			/// Convert it to a Google Cloud Timestamp
			Timestamp yesterday = Timestamp.of(cal.getTime());

			/// Build the Database Query:
			/// We only want to search through "UserLog" entities
			/// CompositeFilter allows us to combine multiple conditions (AND)
			/// Condition A: The log MUST belong to this specific user (The "Parent" folder)
			/// Condition B: The login time MUST be Greater than or Equal (ge) to yesterday
			/// Restrict the database to return a maximum of 3 logs, saving read costs and memory
			Query<Entity> query = Query.newEntityQueryBuilder()
					.setKind("UserLog")
					.setFilter(
							CompositeFilter.and(
									StructuredQuery.PropertyFilter.hasAncestor(
											datastore.newKeyFactory().setKind("User").newKey(data.username)),
									PropertyFilter.ge(USER_LOGIN_TIME, yesterday)
							)
					)
					.setOrderBy(OrderBy.desc(USER_LOGIN_TIME))
					.setLimit(3)
					.build();

			/// Execute the query in that base and store the results
			QueryResults<Entity> logs = datastore.run(query);

			/// Create an empty list to hold the final dates we want to show the user
			List<Date> loginDates = new ArrayList<>();

			/// Loop through every log the database found
			/// Extract the timestamp, convert it to a standard Java Date, and add it to our list
			logs.forEachRemaining(userlog -> {
				loginDates.add(userlog.getTimestamp(USER_LOGIN_TIME).toDate());
			});

			return Response.ok(g.toJson(loginDates)).build();
		}
		return Response.status(Status.FORBIDDEN).
				entity(MESSAGE_INVALID_CREDENTIALS)
				.build();
	}


	// task5
	@POST
	@Path("/user/pagination")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response getLatestLogins(@QueryParam("next") String nextParam, LoginData data) {		/// @QueryParam -> instead of just receiving a JSON body, also expects a variable directly in the URL called next
																								/// ex: http://localhost:8080/rest/login/user/pagination/?next=0

		int next;

		/// Checks if the variable provided in the URL is a valid number and isn't a negative number before talking to the database
		try {
			next = Integer.parseInt(nextParam);
			if(next < 0)
				return Response.status(Status.BAD_REQUEST).entity(MESSAGE_NEXT_PARAMETER_INVALID).build();
		}
		catch (NumberFormatException e) {
			return Response.status(Status.BAD_REQUEST).entity(MESSAGE_NEXT_PARAMETER_INVALID).build();
		}

		Key userKey = userKeyFactory.newKey(data.username);

		Entity user = datastore.get(userKey);
		if( user != null && user.getString(USER_PWD).equals(DigestUtils.sha512Hex(data.password))) {

			/// same as v2
			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.DATE, -1);
			Timestamp yesterday = Timestamp.of(cal.getTime());

			/// only difference is, we only grab 3 records (setLimit(3)) and we skip the first [next] records in the list (we already showed them to the user on the previous page)
			Query<Entity> query = Query.newEntityQueryBuilder()
					.setKind("UserLog")
					.setFilter(
							CompositeFilter.and(
									PropertyFilter.hasAncestor(
											datastore.newKeyFactory().setKind("User").newKey(data.username)),
									PropertyFilter.ge(USER_LOGIN_TIME, yesterday)
							)
					)
					.setOrderBy(OrderBy.desc(USER_LOGIN_TIME))
					.setLimit(3)
					.setOffset(next)
					.build();
			QueryResults<Entity> logs = datastore.run(query);

			List<Date> loginDates = new ArrayList<>();
			logs.forEachRemaining(userlog -> {
				loginDates.add(userlog.getTimestamp(USER_LOGIN_TIME).toDate());
			});

			return Response.ok(g.toJson(loginDates)).build();
		}
		return Response.status(Status.FORBIDDEN).
				entity(MESSAGE_INVALID_CREDENTIALS)
				.build();
	}





}
