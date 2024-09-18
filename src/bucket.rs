use std::{
    path::PathBuf,
    error::Error
};

use aws_sdk_s3 as s3;
use aws_config::load_from_env;

use s3::{
    Client,
    types::{
        BucketLocationConstraint, 
        CreateBucketConfiguration
    },
    operation::put_object::PutObjectOutput,
    primitives::ByteStream,
    presigning::PresigningConfig
};

//use tokio::time::Duration;
use std::time::Duration;





pub async fn create_bucket(
    client: &Client,
    bucket_name: &str,
) -> Result<(), s3::Error> {
    let constraint = BucketLocationConstraint::from("us-west-1");
    let cfg = CreateBucketConfiguration::builder()
        .location_constraint(constraint)
        .build();

    let create_result = client
        .create_bucket()
        .create_bucket_configuration(cfg)
        .bucket(bucket_name)
        .send().await;

    if create_result.is_ok() {
        println!("S3 bucket was created successfully!");
    } else {
        println!("Error occurred while created s3 bucket!");
        println!("{:?}", create_result.err());
    }
    
    Ok(())
}

pub async fn upload_object(
    bucket_name: &str,
    key: &str,
    file_path: &PathBuf,
    // file_field: &FileField,
) -> Result<PutObjectOutput, s3::Error> {
    let config = load_from_env().await;
    let s3_client = Client::new(&config);
    
    let file = ByteStream::from_path(file_path).await.unwrap();
    // let content_type = &file_field.content_type.unwrap();

    let mut buckets = s3_client.list_buckets().into_paginator().send();
    let mut bucket_exists = false;
    let content_type = format!("image/{}", key.split(".").collect::<Vec<&str>>().last().unwrap());
    println!("CONTENT TYPE: {}", &content_type);

    while let Some(Ok(output)) = buckets.next().await {
        for bucket in output.buckets() {
            if bucket.name().unwrap_or_default() == bucket_name {
                bucket_exists = true;
                break;
            }
        }
    }

    if !bucket_exists {
        match create_bucket(&s3_client, bucket_name).await {
            Ok(()) => println!("Bucket created successfully"),
            Err(e) => println!("Error creating bucket: {:?}", e),
        }
    }

    let obj = s3_client.put_object() 
        .bucket(bucket_name)
        .key(key)
        .content_type(content_type.clone())
        .body(file)
        .send().await
        .map_err(s3::Error::from);

    return obj;
}

/// Delete an object from a bucket.
pub async fn remove_object(
    username: &str,
    bucket: &str,
    file_name: &str,
) -> Result<(), s3::Error> {
    let config = load_from_env().await;
    let s3_client = Client::new(&config);

    let path_string= format!("imgs/{}/{}", username.to_lowercase(), file_name);
    // let file_path = Path::new(&path_string);

    s3_client.delete_object()
        .bucket(bucket)
        .key(&path_string)
        .send().await?;

    Ok(())
}

/// Generate a URL for a presigned GET request.
pub async fn get_object_uri(
    bucket_name: &str,
    object: &str,
    expires_in: u64,
) -> Result<String, Box<dyn Error>> {
    let config = load_from_env().await;
    let s3_client = Client::new(&config);

    let expires_in = Duration::from_secs(expires_in);   
    let presigned_request = s3_client.get_object()
        .bucket(bucket_name)
        .key(object)
        .presigned(PresigningConfig::expires_in(expires_in)?)
        .await?;

    let uri = presigned_request.uri();

    println!("Object URI: {}", presigned_request.uri());
    let valid_until = chrono::offset::Local::now() + expires_in;
    println!("Valid until: {valid_until}");

    Ok(uri.into())
}

pub async fn list_objects(
    bucket_name: &str,
    prefix: Option<&str>
) -> Result<Vec<String>, s3::Error> {
    let config = load_from_env().await;
    let s3_client = Client::new(&config);

    let mut objects = Vec::new();
    let mut list_objects = s3_client.list_objects_v2()
        .bucket(bucket_name)
        .prefix(prefix.unwrap_or(""))
        .into_paginator()
        .send();

    while let Some(Ok(output)) = list_objects.next().await {
        for object in output.contents() {
            objects.push(object.key().unwrap().to_string());
        }
    }

    Ok(objects)
}