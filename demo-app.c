/*
 * demo-app.c
 *
 * Demo application demonstrating the intended use of the LTTng notification API
 *
 * Copyright 2017 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <lttng/domain.h>
#include <lttng/action/action.h>
#include <lttng/action/notify.h>
#include <lttng/condition/condition.h>
#include <lttng/condition/buffer-usage.h>
#include <lttng/condition/evaluation.h>
#include <lttng/notification/channel.h>
#include <lttng/notification/notification.h>
#include <lttng/trigger/trigger.h>
#include <lttng/endpoint.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>

int handle_condition(
		const struct lttng_condition *condition,
		const struct lttng_evaluation *condition_evaluation);

int enable_all_events_in_channel(const char *session_name,
		enum lttng_domain_type domain,
		const char *channel_name);
int disable_all_events_in_channel(const char *session_name,
		enum lttng_domain_type domain,
		const char *channel_name);

void register_and_subscribe_size_trigger(const char *session_name,
		uint64_t size, struct lttng_notification_channel *channel)
{
	int ret;
	enum lttng_condition_status condition_status;
	enum lttng_notification_channel_status channel_status;
	struct lttng_condition *condition;
	struct lttng_action *action;
	struct lttng_trigger *trigger;

	action = lttng_action_notify_create();
	assert(action);

	condition = lttng_condition_session_consumed_size_create();
	assert(condition);

	condition_status = lttng_condition_session_consumed_size_set_threshold(
		condition, size);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);
	condition_status = lttng_condition_session_consumed_size_set_session_name(
		condition, session_name);
	assert(condition_status == LTTNG_CONDITION_STATUS_OK);

	trigger = lttng_trigger_create(condition, action);
	assert(trigger);

	ret = lttng_register_trigger(trigger);
	assert(!ret);
	lttng_trigger_destroy(trigger);
	trigger = NULL;

	lttng_action_destroy(action);
	action = NULL;

	channel_status = lttng_notification_channel_subscribe(channel,
		condition);
	assert(channel_status == LTTNG_NOTIFICATION_CHANNEL_STATUS_OK);
}

/*
 * This application demonstrates the intended use of the new LTTng notification
 * API.
 *
 * This application assumes that an existing session, named "my_session", has
 * already been setup. This session contains a single user space channel,
 * "my_ust_channel".
 *
 * Error checking has been omitted for the sake of brevity.
 */
int main(int argc, char **argv)
{
	int ret = 0;
	int notifs_handled = 0;
	enum lttng_condition_status condition_status;
	struct lttng_notification_channel *notification_channel;
	struct lttng_condition *condition;
	struct lttng_action *action;
	struct lttng_trigger *trigger;

	/*
	 * Open a notification channel.
	 *
	 * A notification channel connects the application to the LTTng session
	 * daemon using a UNIX socket. This "notification channel" can be used
	 * to listen for various types of notifications.
	 *
	 * Multiple independent notification channels can be opened by an
	 * application, and multiple applications can open notification channels
	 * to the session daemon.
	 *
	 * Within the scope of this feature, a notification channel can be used
	 * to be notified that two conditions occurred:
	 *
	 *   1) Buffer usage high-threshold exceeded
	 *   2) Buffer usage low-threshold 
	 *
	 *
	 * However, this communication channel may be extended, in the future,
	 * to allow monitoring applications to be notified of various events,
	 * such as:
	 *
	 *   - creation of new sessions,
	 *   - activation (enable) of a new event within a session,
	 *   - the loss of the connection to a relay daemon,
	 *   - etc.
	 *
	 * Note that notification channels are subject to the same security
	 * rules as the rest of the LTTng control operations. For instance,
	 * an application must be running as a user (UID) that is part of the
	 * "tracing" group or be root in order to interact with a root
	 * session daemon.
	 */
	notification_channel = lttng_notification_channel_create(
			lttng_session_daemon_notification_endpoint);

	/*
	 * Triggers are a new concept introduced as part of this API.
	 *
	 * A trigger performs an Action when a specific Condition is met.
	 *
	 * For the sake if this example, we will define and register two
	 * triggers:
	 *
	 * Trigger A:
	 *   Condition:
	 *     - The buffer usage of one of the streams of the "my_ust_channel"
	 *       channel has exceeded 75%.
	 *   Action:
	 *     - Emit a notification
	 *
	 * Trigger B:
	 *   Condition:
	 *     - The buffer usage of all streams of the "my_ust_channel" channel
	 *       has fallen below 25%.
	 *   Action:
	 *     - Emit a notification
	 *
	 * Note that both of these conditions are level-triggered.
	 */

	/* Create Trigger A's condition. */
	condition = lttng_condition_buffer_usage_high_create();
	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			condition, 0.75);
	condition_status = lttng_condition_buffer_usage_set_session_name(
			condition, "my_session");
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			condition, "my_ust_channel");
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			condition, LTTNG_DOMAIN_UST);

	/*
	 * Note that we have created a condition without specifying a channel,
	 * and without specifying a domain. The only criteria we have set are:
	 *
	 *   - A buffer usage threshold of 75%
	 *   - A target session name, "my_session"
	 *
	 * This means that this condition will evaluate to "true" for all
	 * channels of the session, in every domain (user space, kernel,
	 * python, etc.).
	 *
	 * The threshold can be expressed in bytes or as a ratio.
	 *
	 * In our case, since we want to target all channels of the session, it
	 * makes more sense to express our condition as a ratio since the
	 * various channels could use buffer sizes that are very different.
	 */

	/*
	 * Create the desired "action" to take when the condition defined above
	 * is met.
	 *
	 * In the scope of this feature, the only "action" we are interested in
	 * is "emit notification".
	 */
	action = lttng_action_notify_create();

	/* A trigger associates a condition and an action. */
	trigger = lttng_trigger_create(condition, action);

	/*
	 * Register the trigger to LTTng.
	 *
	 * LTTng will evaluate the condition specified and trigger the action
	 * that was associated to it everytime it is met.
	 */
	ret = lttng_register_trigger(trigger);

	/*
	 * Now that we have registered a trigger, a notification will be emitted
	 * everytime its condition is met.
	 *
	 * In order to receive this notification, we must signify our interest
	 * in these notifications by subscribing to notifications that
	 * match the same condition.
	 */
	lttng_notification_channel_subscribe(notification_channel, condition);

	/* Clean-up */
	lttng_trigger_destroy(trigger);


	/* Create Trigger B, register it, and subscribe to its notifications. */
	condition = lttng_condition_buffer_usage_low_create();
	condition_status = lttng_condition_buffer_usage_set_threshold_ratio(
			condition, 0.25);
	condition_status = lttng_condition_buffer_usage_set_session_name(
			condition, "my_session");
	condition_status = lttng_condition_buffer_usage_set_channel_name(
			condition, "my_ust_channel");
	condition_status = lttng_condition_buffer_usage_set_domain_type(
			condition, LTTNG_DOMAIN_UST);
	action = lttng_action_notify_create();
	trigger = lttng_trigger_create(condition, action);

	lttng_register_trigger(trigger);
	lttng_notification_channel_subscribe(notification_channel, condition);

	register_and_subscribe_size_trigger("my_session", 512 * 1024 * 1024,
			notification_channel);

	/* Clean-up */
	lttng_trigger_destroy(trigger);

	for (;;) {
		struct lttng_notification *notification;
		enum lttng_notification_channel_status status;
		const struct lttng_evaluation *notification_evaluation;
		const struct lttng_condition *notification_condition;

		/* Receive the next notification. */
		status = lttng_notification_channel_get_next_notification(
				notification_channel,
				&notification);
		notifs_handled++;

		switch (status) {
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_OK:
			break;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_NOTIFICATIONS_DROPPED:
			/*
			 * The session daemon can drop notifications if a
			 * monitoring application is not consuming the
			 * notifications fast enough.
			 *
			 * The amount of notifications buffered by the session
			 * daemon is configurable.
			 */
			continue;
		case LTTNG_NOTIFICATION_CHANNEL_STATUS_CLOSED:
			/*
			 * The notification channel has been closed by the
			 * session daemon. This is typically caused by a session
			 * daemon shutting down (cleanly or because of a crash).
			 */
			goto end;
		default:
			/* Unhandled conditions / errors. */
			ret = 1;
			goto end;
		}

		/*
		 * A notification can provide, amongst other things:
		 *   - the condition that caused this notification to be emitted
		 *   - the condition evaluation, which provides more specific
		 *     information on the evaluation of the condition.
		 *
		 * In our specific case, the condition will let us know whether
		 * the high or low threshold was hit.
		 *
		 * The condition evaluation provides the buffer usage value
		 * at the moment the condition was met.
		 */
		notification_condition = lttng_notification_get_condition(
				notification);
		notification_evaluation = lttng_notification_get_evaluation(
				notification);

		ret = handle_condition(notification_condition,
				notification_evaluation);
		lttng_notification_destroy(notification);
		if (ret != 0) {
			goto end;
		}
	}
end:
	lttng_notification_channel_destroy(notification_channel);
	return ret;
}

int handle_condition(
		const struct lttng_condition *condition,
		const struct lttng_evaluation *evaluation)
{
	int ret = 0;
	enum lttng_condition_type condition_type;

	condition_type = lttng_condition_get_type(condition);

	switch (condition_type) {
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_HIGH:
	{
		const char *session_name = NULL;
		const char *channel_name = NULL;
		enum lttng_domain_type domain = LTTNG_DOMAIN_NONE;
		double buffer_usage;

		/*
		 * Trigger A, which we defined earlier, has been triggered.
		 *
		 * We can deduce that the condition evaluation type is
		 * lttng_evaluation_buffer_usage
		 *
		 * The condition evaluation object is used to determine the
		 * session, domain, and channel of the buffer which triggered
		 * this notification.
		 *
		 * We can also retrieve the buffer's usage at the time of the
		 * evaluation of the notification.
		 */
		lttng_evaluation_buffer_usage_get_usage_ratio(
				evaluation, &buffer_usage);
		buffer_usage *= 100.0;
		lttng_condition_buffer_usage_get_session_name(condition,
				&session_name);
		lttng_condition_buffer_usage_get_channel_name(condition,
				&channel_name);

		/* Log that this condition happened. */
		printf("High threshold condition met in session \"%s\", channel \"%s\". The usage at the time of evaluation was of %f\%\n",
				session_name, channel_name, buffer_usage);

		/*
		 * Since the buffer usage is higher than the threshold we have
		 * set, we can decide to disable all events associated with the
		 * channel in which a buffer exceeeded our threshold.
		 */
		ret = disable_all_events_in_channel(session_name, domain,
				channel_name);
		break;
	}
	case LTTNG_CONDITION_TYPE_BUFFER_USAGE_LOW:
	{
		const char *session_name = NULL;
		const char *channel_name = NULL;
		enum lttng_domain_type domain = LTTNG_DOMAIN_NONE;
		double buffer_usage;

		/*
		 * Trigger B, which we defined earlier, has been triggered.
		 *
		 * Since the buffer usage is lower than the threshold we have
		 * set, we can take an arbitrary action. In this case, we decide
		 * to re-enable all events associated with the channel.
		 */
		lttng_evaluation_buffer_usage_get_usage_ratio(
				evaluation, &buffer_usage);
		buffer_usage *= 100.0;
		lttng_condition_buffer_usage_get_session_name(condition,
				&session_name);
		lttng_condition_buffer_usage_get_channel_name(condition,
				&channel_name);

		/* Log that this condition happened. */
		printf("Low threshold condition met in session \"%s\", channel \"%s\". The usage at the time of evaluation was of %f\%\n",
				session_name, channel_name, buffer_usage);

		/*
		 * Retrieve info from condition and condition evaluation
		 * similarily to the example above.
		 */
		ret = enable_all_events_in_channel(session_name, domain,
				channel_name);
		break;
	}
	case LTTNG_CONDITION_TYPE_SESSION_CONSUMED_SIZE:
		printf("Got a condition session consumed size notification!\n");
		exit(0);
		break;
	default:
		/* Unexpected condition type. */
		ret = 1;
		goto end;
	}
end:
	return ret;
}

int enable_all_events_in_channel(const char *session_name,
		enum lttng_domain_type domain,
		const char *channel_name)
{
	/* Not implemented. */
	return 0;
}

int disable_all_events_in_channel(const char *session_name,
		enum lttng_domain_type domain,
		const char *channel_name)
{
	/* Not implemented. */
	return 0;
}

