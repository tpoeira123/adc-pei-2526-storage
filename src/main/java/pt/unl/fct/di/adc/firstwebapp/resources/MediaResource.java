package pt.unl.fct.di.adc.firstwebapp.resources;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URL;
import java.util.concurrent.TimeUnit;

import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.HttpMethod;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.StreamingOutput;
import jakarta.ws.rs.core.Response.Status;

@Path("/media")
public class MediaResource {

    /**
     * THE EFFICIENT DOWNLOAD (Streaming)
     * This is the recommended way to serve files from Google Cloud Storage (GCS) to a client.
     */
    @GET
    @Path("/download/{bucket}/{object}")
    public Response downloadFile(@PathParam("bucket") String bucket, @PathParam("object") String object) {

        /// Connect to GCS and find the file (Blob) using the bucket name and file name.
        Storage storage = StorageOptions.getDefaultInstance().getService();
        Blob blob = storage.get(BlobId.of(bucket, object));

        /// Create a StreamingOutput.
        /// Instead of loading a 500MB video into the server's RAM all at once, it acts as a pipe.
        /// As the server downloads the file from GCS, it immediately forwards
        /// those chunks to the client. It keeps the server's memory usage very low!
        StreamingOutput stream = output -> {
            blob.downloadTo(output); /// Pipes data from GCS directly to the HTTP response
            output.flush();
        };

        return Response.ok(stream)
                .header("Content-Type", blob.getContentType())
                .build();
    }

    /**
     * THE DANGEROUS DOWNLOAD (In-Memory)
     * This approach should generally be avoided for large files.
     */
    @GET
    @Path("/download2/{bucket}/{object}")
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    public Response downloadFile2(@PathParam("bucket") String bucket, @PathParam("object") String object) {

        Storage storage = StorageOptions.getDefaultInstance().getService();
        Blob blob = storage.get(BlobId.of(bucket, object));

        /// WHY THIS IS BAD: blob.getContent() downloads the ENTIRE file into a byte[] array
        /// in the server's RAM before sending a single byte to the client.
        /// If 10 users try to download a 100MB file at the same time, your server will
        /// consume 1GB of RAM instantly and likely crash with an OutOfMemoryError.
        return Response.ok(blob.getContent())
                .header("Content-Type", blob.getContentType())
                .build();
    }



    /**
     * THE SCALABLE UPLOAD (Signed URLs)
     * This is the industry-standard way to handle file uploads in cloud architecture.
     */
    @POST
    @Path("/upload/{bucket}/{object}")
    public Response uploadFile(@PathParam("bucket") String bucket, @PathParam("object") String object,
                               @HeaderParam("Content-Type") String contentType) {

        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of(bucket, object);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType(contentType).build();

        /// Instead of processing the upload, your server acts like a ticket booth.
        /// It asks GCS to generate a secure, temporary "Signed URL".
        URL url = storage.signUrl(blobInfo, 15, TimeUnit.MINUTES,
                Storage.SignUrlOption.httpMethod(HttpMethod.PUT),
                Storage.SignUrlOption.withContentType(),
                Storage.SignUrlOption.withV4Signature());

        /// You send this URL back to the client.
        /// The client then does a PUT request directly to this Google URL to upload the file.
        /// This saves your server from doing heavy lifting and saves massive amounts of bandwidth.
        return Response.ok(url.toString()).build();
    }

    /**
     * THE BOTTLENECK UPLOAD (Server as Middleman)
     * As the original author's comment says, this approach is deprecated/discouraged.
     */
    @POST
    @Path("/upload2/{bucket}/{object}")
    public Response uploadFile2(@PathParam("bucket") String bucket, @PathParam("object") String object,
                                @HeaderParam("Content-Type") String contentType,
                                @Context HttpServletRequest request) {

        Storage storage = StorageOptions.getDefaultInstance().getService();
        BlobId blobId = BlobId.of(bucket, object);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).setContentType(contentType).build();

        /// WHY THIS IS BAD: The user uploads the file to your App Engine server, and then your App Engine server uploads it to GCS.
        /// 1. You pay for bandwidth twice (Client -> Server, Server -> GCS).
        /// 2. It ties up server connections for a long time if the user has slow internet.
        /// 3. App Engine has strict timeout limits (usually 60 seconds), so big uploads will fail.
        try {
            storage.createFrom(blobInfo, request.getInputStream());
            return Response.ok().build();
        } catch (IOException e) {
            return Response.status(Status.INTERNAL_SERVER_ERROR).build();
        }
    }
}