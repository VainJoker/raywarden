//! Commit sensitive account actions against the authorization that verified them.
use worker::{D1Database, D1PreparedStatement};

use super::{
    device::{DeviceRow, SessionSnapshot},
    email::VerifiedCode,
    user::UserRow,
};
use crate::{
    errors::{AppError, AppResult, DatabaseError, DbSentinel},
    infra::db,
    models::mutation,
};

pub(crate) struct VerifiedAccountAction<'a> {
    pub(crate) session: SessionSnapshot<'a>,
    user: UserRow,
    otp: Option<VerifiedCode>,
}

impl<'a> VerifiedAccountAction<'a> {
    pub(crate) fn new(
        session: SessionSnapshot<'a>,
        user: UserRow,
        otp: Option<VerifiedCode>,
    ) -> AppResult<Self> {
        if user.id != session.user_id || user.security_stamp != session.security_stamp {
            return Err(action_conflict());
        }
        Ok(Self { session, user, otp })
    }

    pub(super) async fn commit(
        &self,
        db: &D1Database,
        mut writes: Vec<D1PreparedStatement>,
        context: &'static str,
    ) -> AppResult<()> {
        writes.splice(..0, [
            session_guard(db, &self.session)?,
            DeviceRow::guard_current_login_account(db, &self.user)?,
        ]);
        VerifiedCode::commit(
            db,
            &self.otp,
            writes,
            |error| match DatabaseError::find_sentinel(&error, &[
                DbSentinel::VaultWriteConflict,
                DbSentinel::TotpWriteConflict,
            ]) {
                Some(DbSentinel::VaultWriteConflict) => action_conflict(),
                Some(DbSentinel::TotpWriteConflict) => {
                    AppError::conflict("Authenticator configuration changed; retry")
                }
                _ => DatabaseError::query(context, &error),
            },
        )
        .await
    }
}

pub(crate) fn session_guard(
    db: &D1Database,
    session: &SessionSnapshot<'_>,
) -> AppResult<D1PreparedStatement> {
    session_guard_with_sentinel(db, session, DbSentinel::VaultWriteConflict)
}

pub(crate) fn session_guard_with_sentinel(
    db: &D1Database,
    session: &SessionSnapshot<'_>,
    sentinel: DbSentinel,
) -> AppResult<D1PreparedStatement> {
    mutation::guard_with_sentinel(
        db,
        "EXISTS(SELECT 1 FROM users u JOIN devices d ON d.user_id=u.id WHERE \
         u.id=?1 AND u.security_stamp=?2 AND d.device_id=?3 AND d.session_token=?4)",
        &db::d1_params![
            session.user_id,
            session.security_stamp,
            session.device_id,
            session.session_token
        ],
        sentinel,
    )
}

pub(crate) fn map_session_write_error(context: &'static str, error: &worker::Error) -> AppError {
    match DatabaseError::find_sentinel(error, &[DbSentinel::VaultWriteConflict]) {
        Some(DbSentinel::VaultWriteConflict) => action_conflict(),
        _ => DatabaseError::query(context, error),
    }
}

fn action_conflict() -> AppError {
    AppError::conflict("Account, session or security settings changed; retry")
}
