import os
import logging
from flask import Flask, request, make_response
from slack import WebClient
from slackeventsapi import SlackEventAdapter
import ssl as ssl_lib
import certifi
from slack.errors import SlackApiError
import json
import tweepy

# Initialize a Flask app to host the events adapter
app = Flask(__name__)
slack_events_adapter = SlackEventAdapter(os.environ["SLACK_SIGNING_SECRET"], "/slack/events", app)

# Initialize a Web API client
slack_web_client = WebClient(token=os.environ['SLACK_BOT_TOKEN'])


auth = tweepy.OAuthHandler(os.environ['CONSUMER_KEY'], os.environ['CONSUMER_SECRET'])
auth.set_access_token(os.environ['ACCESS_TOKEN'], os.environ['ACCESS_TOKEN_SECRET'])
api = tweepy.API(auth)

# ============== Message Events ============= #
# When a user sends a DM, the event type will be 'message'.
# Here we'll link the message callback to the 'message' event.
@slack_events_adapter.on("message")
def message(payload):
    """Display the onboarding welcome message after receiving a message
    that contains "start".
    """
    event = payload.get("event", {})
    # print(event)
    channel_id = event.get("channel")
    user_id = event.get("user")
    # text = event.get("text")

    # print(text)
    # print(user_id)
    # print(text.lower())

    # if event.get("subtype") is None and "start" in event.get('text'):
    #     return start_onboarding(user_id, channel_id)
    if event.get("subtype") is None and ".slack" in event.get('text'):
        text = event.get("text")
        print(text.partition(' '))
        text= text.partition(' ')[2]
        # print(text)
        text= text.partition(' ')[2]
        # print(text)
        target_channel = text.partition(' ')[0].split('|')[0][2:]
        message = text.partition(' ')[2]
        print(text)
        print(target_channel)
        print(message)
        return slack_web_client.chat_postMessage(channel= target_channel, text= message)

    if event.get("subtype") is None and ".tweet" in event.get('text'):
        text = event.get("text")
        print(text.partition(' '))
        text = text.partition(' ')[2]
        # print(text)
        message = text.partition(' ')[2]
        # print(text)
        print(message)
        return api.update_status(message)

print(slack_web_client.channels_list())

def verify_request(
    signing_secret: str,
    request_body: str,
    timestamp: str,
    signature: str) -> bool:
    if abs(time() - int(timestamp)) > 60 * 5:
        return False

    if hasattr(hmac, "compare_digest"):
        req = str.encode('v0:' + str(timestamp) + ':') + request_body
        request_hash = 'v0=' + hmac.new(
            str.encode(signing_secret),
            req, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(request_hash, signature)
    else:
        # So, we'll compare the signatures explicitly
        req = str.encode('v0:' + str(timestamp) + ':') + request_body
        request_hash = 'v0=' + hmac.new(
            str.encode(signing_secret),
            req, hashlib.sha256
        ).hexdigest()

        if len(request_hash) != len(signature):
            return False
        result = 0
        if isinstance(request_hash, bytes) and isinstance(signature, bytes):
            for x, y in zip(request_hash, signature):
                result |= x ^ y
        else:
            for x, y in zip(request_hash, signature):
                result |= ord(x) ^ ord(y)
        return result == 0

signing_secret = os.environ["SLACK_SIGNING_SECRET"]

@app.route("/postinchannel", methods=["POST"])
def test():
  if "command" in request.form \
    and request.form["command"] == "/postinchannel":
    trigger_id = request.form["trigger_id"]
    try:
      response = slack_web_client.views_open(
        trigger_id=trigger_id,
        view={
            "type": "modal",
            "callback_id": "modal-id",
            "title": {
                "type": "plain_text",
                "text": "Post in a channel"
            },
            "submit": {
                "type": "plain_text",
                "text": "Submit"
            },
            "close": {
                "type": "plain_text",
                "text": "Cancel"
            },
            "blocks": [
                {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": "Use this form to post message in a slack channel."
                }
                },
                {
                "type": "divider"
                },
                {
                "type": "input",
                "block_id": "b1-id",
                "label": {
                "type": "plain_text",
                "text": "Pick channels from the list"
                },
                "element": {
                "action_id": "a1-id",
                "type": "multi_channels_select",
                "placeholder": {
                    "type": "plain_text",
                    "text": "Select channels"
                }
                }
                },
                {
                    "type": "input",
                    "block_id": "b2-id",
                    "label": {
                        "type": "plain_text",
                        "text": "Message",
                    },
                    "element": {
                        "action_id": "a2-id",
                        "multiline": True,
                        "type": "plain_text_input",
                    }
                }
            ]
        }
      )
      return make_response("", 200)
    except SlackApiError as e:
      code = e.response["error"]
      return make_response(f"Failed to open a modal due to {code}", 200)

  elif "payload" in request.form:
    payload = json.loads(request.form["payload"])
    # print(json.dumps(payload, indent=1))
    if payload["type"] == "block_actions" \
      and payload["view"]["callback_id"] == "modal-id":
    #   if payload["actions"]["type"] == "multi_channel_select":
      return 200

    if payload["type"] == "view_submission" \
      and payload["view"]["callback_id"] == "modal-id":
      submitted_data = payload["view"]["state"]["values"]
      print(submitted_data)  # {'b-id': {'a-id': {'type': 'plain_text_input', 'value': 'your input'}}}
      message = submitted_data['b2-id']['a2-id']['value']
      for i in submitted_data['b1-id']['a1-id']['selected_channels']:
        slack_web_client.chat_postMessage(channel= i, text= message)
      return make_response("", 200)

    if payload["type"] == "view_submission" \
      and payload["view"]["callback_id"] == "modal-id-tweet":
      submitted_data = payload["view"]["state"]["values"]
      print(submitted_data)  # {'b-id': {'a-id': {'type': 'plain_text_input', 'value': 'your input'}}}
      message = submitted_data['b2-id']['a2-id']['value']
      api.update_status(message)
      return make_response("", 200)

  return make_response("", 404)

@app.route("/tweet", methods=["POST"])
def tweet():
  if "command" in request.form \
    and request.form["command"] == "/tweet":
    trigger_id = request.form["trigger_id"]
    try:
      response = slack_web_client.views_open(
        trigger_id=trigger_id,
        view={
            "type": "modal",
            "callback_id": "modal-id-tweet",
            "title": {
                "type": "plain_text",
                "text": "Tweet a message"
            },
            "submit": {
                "type": "plain_text",
                "text": "Submit"
            },
            "close": {
                "type": "plain_text",
                "text": "Cancel"
            },
            "blocks": [
                {
                "type": "section",
                "text": {
                    "type": "plain_text",
                    "text": "Use this form to tweet a status."
                }
                },
                {
                "type": "divider"
                },
                {
                    "type": "input",
                    "block_id": "b2-id",
                    "label": {
                        "type": "plain_text",
                        "text": "Message",
                    },
                    "element": {
                        "action_id": "a2-id",
                        "multiline": True,
                        "type": "plain_text_input",
                    }
                }
            ]
        }
      )
      return make_response("", 200)
    except SlackApiError as e:
      code = e.response["error"]
      return make_response(f"Failed to open a modal due to {code}", 200)

  elif "payload" in request.form:
    payload = json.loads(request.form["payload"])
    # print(json.dumps(payload, indent=1))
    if payload["type"] == "block_actions" \
      and payload["view"]["callback_id"] == "modal-id":
    #   if payload["actions"]["type"] == "multi_channel_select":
      return 200

    if payload["type"] == "view_submission" \
      and payload["view"]["callback_id"] == "modal-id":
      submitted_data = payload["view"]["state"]["values"]
      print(submitted_data)  # {'b-id': {'a-id': {'type': 'plain_text_input', 'value': 'your input'}}}
      message = submitted_data['b2-id']['a2-id']['value']
      for i in submitted_data['b1-id']['a1-id']['selected_channels']:
        slack_web_client.chat_postMessage(channel= i, text= message)
      return make_response("", 200)

  return make_response("", 404)

if __name__ == "__main__":
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
    ssl_context = ssl_lib.create_default_context(cafile=certifi.where())
    app.run(port=3000)