---
title: "Image Analysis Process"
linkTitle: "Image Analysis"
weight: 1
---

Image analysis is performed as a distinct, asynchronous, and scheduled task driven by queues that analyzer workers periodically poll. Image records have a small state-machine as follows:

![alt text](ImageAnalysisState.jpg)

The analysis process is composed of several steps and utilizes several system components. The, basic flow of that task is as follows:

![alt text](ImageAnalysisTask.jpg)

Adding more detail, the API call trace between services looks approximately like (somewhat simplified for ease of presentation):

![alt text](ImageAnalysisAPI.jpg)

### Next Steps

Now let's get familiar with [Watching Images and Tags]({{< ref "/docs/general/concepts/images/watchers" >}}) with Anchore.
