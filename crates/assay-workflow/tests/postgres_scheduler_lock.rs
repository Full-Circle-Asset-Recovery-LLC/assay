//! Real-Postgres regressions for the scheduler advisory-lock connection.

mod common;

use std::time::Duration;

use assay_workflow::{PostgresStore, WorkflowStore};
use common::harness::{TestPostgresDatabase, TestPostgresServer};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};

const CHECK_TIMEOUT: Duration = Duration::from_secs(2);

async fn test_database() -> Option<TestPostgresDatabase> {
    let configured_database = std::env::var("TEST_DATABASE_URL")
        .ok()
        .is_some_and(|url| !url.is_empty());
    let server = match TestPostgresServer::from_env_or_container().await {
        Ok(server) => server,
        Err(error) if configured_database => {
            panic!("configured TEST_DATABASE_URL is unavailable: {error:#}");
        }
        Err(error) => {
            eprintln!("Skipping: Postgres unavailable: {error:#}");
            return None;
        }
    };

    Some(TestPostgresDatabase::create(server).await.unwrap())
}

async fn store_pool(database: &TestPostgresDatabase, max_connections: u32) -> PgPool {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with((*database.pool().connect_options()).clone())
        .await
        .unwrap()
}

async fn scheduler_owner_pid(observer: &PgPool) -> i32 {
    sqlx::query_scalar(
        "SELECT l.pid
         FROM pg_locks l
         JOIN pg_database d ON d.oid = l.database
         WHERE l.locktype = 'advisory'
           AND l.classid = 0
           AND l.objid = 42
           AND l.objsubid = 1
           AND l.granted
           AND d.datname = current_database()",
    )
    .fetch_one(observer)
    .await
    .unwrap()
}

async fn acquire_with_timeout(store: &PostgresStore) -> anyhow::Result<bool> {
    tokio::time::timeout(CHECK_TIMEOUT, store.try_acquire_scheduler_lock())
        .await
        .expect("scheduler lock check exceeded its bound")
}

#[tokio::test]
async fn scheduler_lock_survives_data_pool_churn_across_ticks() {
    let Some(database) = test_database().await else {
        return;
    };
    let pool = store_pool(&database, 2).await;
    let store = PostgresStore::from_pool(pool.clone()).await.unwrap();

    assert!(acquire_with_timeout(&store).await.unwrap());

    let first_data_connection = pool.acquire().await.unwrap();
    let second_data_connection = pool.acquire().await.unwrap();

    for _ in 0..3 {
        assert!(
            acquire_with_timeout(&store).await.unwrap(),
            "the scheduler owner must remain stable while the data pool is busy"
        );
    }

    drop((first_data_connection, second_data_connection));
}

#[tokio::test]
async fn scheduler_lock_connection_is_shared_by_clones_until_the_final_drop() {
    let Some(database) = test_database().await else {
        return;
    };
    let pool = store_pool(&database, 1).await;
    let store = PostgresStore::from_pool(pool.clone()).await.unwrap();
    let clone = store.clone();

    assert!(acquire_with_timeout(&store).await.unwrap());
    let data_connection = pool.acquire().await.unwrap();

    assert!(acquire_with_timeout(&clone).await.unwrap());
    drop(store);
    assert!(acquire_with_timeout(&clone).await.unwrap());

    drop(data_connection);
}

#[tokio::test]
async fn competing_store_acquires_only_after_final_owner_clone_drops() {
    let Some(database) = test_database().await else {
        return;
    };
    let owner_pool = store_pool(&database, 1).await;
    let contender_pool = store_pool(&database, 1).await;
    let owner = PostgresStore::from_pool(owner_pool.clone()).await.unwrap();
    let owner_clone = owner.clone();
    let contender = PostgresStore::from_pool(contender_pool).await.unwrap();

    assert!(acquire_with_timeout(&owner).await.unwrap());
    assert!(!acquire_with_timeout(&contender).await.unwrap());

    drop(owner);
    assert!(!acquire_with_timeout(&contender).await.unwrap());

    drop(owner_clone);
    let acquired_after_final_drop = tokio::time::timeout(CHECK_TIMEOUT, async {
        loop {
            if contender.try_acquire_scheduler_lock().await.unwrap() {
                break true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the final store drop must close the scheduler lock socket");

    assert!(acquired_after_final_drop);
    drop(owner_pool);
}

#[tokio::test]
async fn terminated_owner_fails_closed_then_reacquires_without_stale_ownership() {
    let Some(database) = test_database().await else {
        return;
    };
    let owner_pool = store_pool(&database, 1).await;
    let successor_pool = store_pool(&database, 1).await;
    let owner = PostgresStore::from_pool(owner_pool).await.unwrap();
    let successor = PostgresStore::from_pool(successor_pool).await.unwrap();

    assert!(acquire_with_timeout(&owner).await.unwrap());
    let owner_pid = scheduler_owner_pid(database.pool()).await;

    let terminated = sqlx::query("SELECT pg_terminate_backend($1) AS terminated")
        .bind(owner_pid)
        .fetch_one(database.pool())
        .await
        .unwrap()
        .get::<bool, _>("terminated");
    assert!(terminated);

    assert!(
        acquire_with_timeout(&owner).await.is_err(),
        "a broken owner connection must fail closed for the current tick"
    );
    assert!(acquire_with_timeout(&successor).await.unwrap());
    assert!(
        !acquire_with_timeout(&owner).await.unwrap(),
        "the former owner must not report stale ownership"
    );

    drop(successor);
    let reacquired = tokio::time::timeout(CHECK_TIMEOUT, async {
        loop {
            if owner.try_acquire_scheduler_lock().await.unwrap() {
                break true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the former owner should reacquire after the successor drops");
    assert!(reacquired);
}
