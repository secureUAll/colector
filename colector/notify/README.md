# Notify

[`notify.py`](notify.py) defines an interface for notifications service, based on Builder creational pattern.



## Interface documentation

Each service provides the following methods for text insertion. They all return `None`.

> They <u>all insert a line break in the end</u>. To remove the line break, some (marked in the table below) support the parameter `end`. Example below.
>
> ```python
> .heading("This is a heading", end="")
> ```

| Method   | Argument              | Description    | end param |
| -------- | --------------------- | -------------- | --------- |
| heading  | heading:str           | Text heading   | Yes       |
| text     | text:str              | Simple text    | Yes       |
| olist    | lst:list              | Ordered list   | No        |
| ulist    | lst:list              | Unordered list | No        |
| citation | citation:str          | Citation       | Yes       |
| code     | block:str             | Code block     | No        |
| url      | url:str<br />text:str | Hyperlink      | Yes       |
| brake    | -                     | Line break     | No        |

For decoration, the following methods are available. They all return `None`.

| Method | Argument | Description  | end param |
| ------ | -------- | ------------ | --------- |
| bold   | text:str | Bold text    | Yes       |
| italic | text:str | Italic text  | Yes       |
| label  | text:str | Labeled text | Yes       |

Finally to send the message through the service, use `send(recipient:str) -> int`, which returns the HTTP status code of the sent message process.



## Slack

Slack integration is at file [`slack.py`](slack.py).

>  The Slack integration was created based on an official tutorial that can be found [here](https://api.slack.com/messaging/sending#getting_started).

>  The text is being formatted according to [this](https://www.markdownguide.org/tools/slack/) documentation.

To post a message, just send `POST` request to https://hooks.slack.com/services/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 with the body as exemplified below.

```json
{"text": "Hello, world!"}
```

