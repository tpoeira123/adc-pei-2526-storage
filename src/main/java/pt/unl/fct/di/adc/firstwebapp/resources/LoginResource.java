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


	// task6
	@POST
	@Path("/v2")
	@Consumes(MediaType.APPLICATION_JSON)
	@Produces(MediaType.APPLICATION_JSON)
	public Response doLoginV2(LoginData data,
							  @Context HttpServletRequest request,	/// raw HTTP web request that the client just sent to your server
							  @Context HttpHeaders headers) {		/// is a specialized object that just isolates the HTTP headers (the hidden metadata sent along with every web request)
		LOG.fine(LOG_MESSAGE_LOGIN_ATTEMP + data.username);

		/// Creates the primary Key to look up the User entity based on the provided username.
		Key userKey = userKeyFactory.newKey(data.username);

		/// Creates a Key for the user's statistics (login counts).
		/// 'addAncestors': it makes the User the "parent" of these stats.
		/// This creates an "Entity Group", which allows us to update the user and their stats safely in a single transaction.
		Key ctrsKey = datastore.newKeyFactory()
				.addAncestors(PathElement.of("User", data.username))
				.setKind("UserStats")
				.newKey("counters");

		/// Creates a Key for the login audit log.
		/// 'allocateId' asks the database to generate a unique, random ID for this specific log entry
		/// so it doesn't overwrite previous logs. It is also stored as a child of the User.
		Key logKey = datastore.allocateId(
				datastore.newKeyFactory()
						.addAncestors(PathElement.of("User", data.username))
						.setKind("UserLog").newKey());

		/// A transaction ensures that either ALL database writes succeed, or NONE do.
		/// This prevents corrupted data if the server crashes halfway through the login process.
		Transaction txn = datastore.newTransaction();

		try {
			Entity user = txn.get(userKey);
			if (user == null) {
				/// Fail fast: If the username isn't in the database, abort immediately.
				LOG.warning(LOG_MESSAGE_LOGIN_ATTEMP + data.username);
				return Response.status(Status.FORBIDDEN)
						.entity(MESSAGE_INVALID_CREDENTIALS)
						.build();
			}

			Entity stats = txn.get(ctrsKey);
			if (stats == null) {
				/// If this is the user's very first time logging in,
				/// the stats entity won't exist yet. We create a fresh one with counters set to 0.
				stats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", 0L)
						.set("user_stats_failed", 0L)
						.set("user_first_login", Timestamp.now())
						.set("user_last_login", Timestamp.now())
						.build();
			}

			/// Retrieves the hashed password from the database and compares it
			String hashedPWD = user.getString(USER_PWD);
			if (hashedPWD.equals(DigestUtils.sha512Hex(data.password))) {

				/// LOGIN ACCEPTED (right password)

				/// Extracts the user's location and IP data from App Engine's automatic HTTP headers.
				String cityLatLong = headers.getHeaderString("X-AppEngine-CityLatLong");
				Entity log = Entity.newBuilder(logKey)
						.set("user_login_ip", request.getRemoteAddr())
						.set("user_login_host", request.getRemoteHost())
						/// Only saves Lat/Long if it exists, and excludes it from database indexes to save costs
						.set("user_login_latlon", cityLatLong != null
								? StringValue.newBuilder(cityLatLong).setExcludeFromIndexes(true).build()
								: StringValue.newBuilder("").setExcludeFromIndexes(true).build())
						.set("user_login_city", headers.getHeaderString("X-AppEngine-City"))
						.set("user_login_country", headers.getHeaderString("X-AppEngine-Country"))
						.set("user_login_time", Timestamp.now())
						.build();

				/// "Copying information every time a user logins may not be a good solution (why?)"
				/// Answer: Because if you add a new field to UserStats in the future, you have to remember
				/// to manually copy it here, otherwise it will get deleted. It's also inefficient.
				Entity ustats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", stats.getLong("user_stats_logins") + 1)
						.set("user_stats_failed", 0L) // Reset failed attempts back to 0
						.set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", Timestamp.now())
						.build();

				/*
				  THE BETTER SOLUTION (For future reference):
				  Instead of copying manually, build upon the existing entity:
				  Entity ustats = Entity.newBuilder(stats)  <-- Pass 'stats' here!
				  .set("user_stats_logins", stats.getLong("user_stats_logins") + 1)
				  .set("user_stats_failed", 0L)
				  .set("user_last_login", Timestamp.now())
				  .build();
				 */

				/// Saves both the log and the updated stats simultaneously.
				txn.put(log, ustats);
				txn.commit(); // Locks in the changes

				/// Generates an access token and returns an HTTP 200 OK.
				AuthToken token = new AuthToken(data.username);
				LOG.info(LOG_MESSAGE_LOGIN_SUCCESSFUL + data.username);
				return Response.ok(g.toJson(token)).build();

			} else {

				/// LOGIN FAILED (Wrong Password)

				/// Original comment: "Copying here is even worse. Propose a better solution!"
				/// Answer: Again, use Entity.newBuilder(stats) so you only have to write the fields that actually changed!
				Entity ustats = Entity.newBuilder(ctrsKey)
						.set("user_stats_logins", stats.getLong("user_stats_logins"))
						.set("user_stats_failed", stats.getLong("user_stats_failed") + 1L) // Increment fail count
						.set("user_first_login", stats.getTimestamp("user_first_login"))
						.set("user_last_login", stats.getTimestamp("user_last_login"))
						.set("user_last_attempt", Timestamp.now())
						.build();

				///  save and rejects
				txn.put(ustats);
				txn.commit(); /// Locks in the updated fail count

				LOG.warning(LOG_MESSAGE_WRONG_PASSWORD + data.username);
				return Response.status(Status.FORBIDDEN).entity(MESSAGE_INVALID_CREDENTIALS).build();
			}

		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			/// A safety net. If the transaction is still somehow active (e.g., a crash happened
			/// before commit() or rollback() could run), force it to close to prevent database deadlocks.
			if (txn.isActive()) {
				txn.rollback();
			}
		}
	}



}
