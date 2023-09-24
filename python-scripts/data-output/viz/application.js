"use strict";
/*
Stix2viz and visjs are packaged in a way that makes them work as Jupyter
notebook extensions.  Part of the extension installation process involves
copying them to a different location, where they're available via a special
"nbextensions" path.  This path is hard-coded into their "require" module
IDs.  Perhaps it's better to use abstract names, and add special config
in all cases to map the IDs to real paths, thus keeping the modules free
of usage-specific hard-codings.  But packaging in a way I know works in
Jupyter (an already complicated environment), and having only this config
here, seemed simpler.  At least, for now.  Maybe later someone can structure
these modules and apps in a better way.
*/
require.config({
    paths: {
      "nbextensions/stix2viz/vis-network": "stix2viz/visjs/vis-network"
    }
});

require(["domReady!", "stix2viz/stix2viz/stix2viz", "temp-json/latest"], function (document, stix2viz, latest_json_file_contents) {
    // Init some stuff
    let view = null;
    let uploader = document.getElementById('uploader');
    let canvasContainer = document.getElementById('canvas-container');
    let canvas = document.getElementById('canvas');

    /**
     * Build a message and display an alert window, from an exception object.
     * This will follow the exception's causal chain and display all of the
     * causes in sequence, to produce a more informative message.
     */
    function alertException(exc, initialMessage=null)
    {
        let messages = [];

        if (initialMessage)
            messages.push(initialMessage);

        messages.push(exc.toString());

        while (exc instanceof Error && exc.cause)
        {
            exc = exc.cause;
            messages.push(exc.toString());
        }

        let message = messages.join("\n\n    Caused by:\n\n");

        alert(message);
    }


    /**
     * Handle clicks on the visjs graph view.
     *
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     */
    function graphViewClickHandler(event, edgeDataSet, stixIdToObject)
    {
        if (event.nodes.length > 0)
        {
            // A click on a node
            let stixObject = stixIdToObject.get(event.nodes[0]);
            if (stixObject)
                populateSelected(stixObject, edgeDataSet, stixIdToObject);
        }
        else if (event.edges.length > 0)
        {
            // A click on an edge
            let stixRel = stixIdToObject.get(event.edges[0]);
            if (stixRel)
                populateSelected(stixRel, edgeDataSet, stixIdToObject);
            else
                // Just make something up to show for embedded relationships
                populateSelected(
                    new Map([["", "(Embedded relationship)"]]),
                    edgeDataSet, stixIdToObject
                );
        }
        // else, just a click on the canvas
    }


    /**
     * Handle clicks on the list view.
     *
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     */
    function listViewClickHandler(event, edgeDataSet, stixIdToObject)
    {
        let clickedItem = event.target;

        if (clickedItem.tagName === "LI")
        {
            let stixId = clickedItem.id;
            let stixObject = stixIdToObject.get(stixId);

            view.selectNode(stixId);

            if (stixObject)
                populateSelected(stixObject, edgeDataSet, stixIdToObject);
            else
                // Just make something up to show for embedded relationships
                populateSelected(
                    new Map([["", "(Embedded relationship)"]]),
                    edgeDataSet, stixIdToObject
                );
        }
    }


    /* ******************************************************
     * Initializes the view, then renders it.
     * ******************************************************/
    function vizStixWrapper(content, customConfig) {

        if (customConfig)
            try
            {
                customConfig = JSON.parse(customConfig);
            }
            catch(err)
            {
                alertException(err, "Invalid configuration: must be JSON");
                return;
            }
        else
            customConfig = {};

        // Hard-coded working icon directory setting for this application.
        customConfig.iconDir = "stix2viz/stix2viz/icons";

        try
        {
            let [nodeDataSet, edgeDataSet, stixIdToObject]
                = stix2viz.makeGraphData(content, customConfig);

            let wantsList = false;
            if (nodeDataSet.length > 200)
                wantsList = confirm(
                    "This graph contains " + nodeDataSet.length.toString()
                    + " nodes.  Do you wish to display it as a list?"
                );

            if (wantsList)
            {
                view = stix2viz.makeListView(
                    canvas, nodeDataSet, edgeDataSet, stixIdToObject,
                    customConfig
                );

                view.on(
                    "click",
                    e => listViewClickHandler(e, edgeDataSet, stixIdToObject)
                );
            }
            else
            {
                view = stix2viz.makeGraphView(
                    canvas, nodeDataSet, edgeDataSet, stixIdToObject,
                    customConfig
                );

                view.on(
                    "click",
                    e => graphViewClickHandler(e, edgeDataSet, stixIdToObject)
                );
            }

            populateLegend(...view.legendData);
        }
        catch (err)
        {
            console.log(err);
            alertException(err);
        }
    }

    /**
     * Toggle the display of graph nodes of a particular STIX type.
     */
    function legendClickHandler(event)
    {
        if (!view)
            return;

        let td;
        let clickedTagName = event.target.tagName.toLowerCase();

        if (clickedTagName === "td")
            // ... if the legend item text was clicked
            td = event.target;
        else if (clickedTagName === "img")
            // ... if the legend item icon was clicked
            td = event.target.parentElement;
        else
            return;

        // The STIX type the user clicked on
        let toggledStixType = td.textContent.trim().toLowerCase();

        view.toggleStixType(toggledStixType);

        // style change to remind users what they've hidden.
        td.classList.toggle("typeHidden");
    }

    /* ******************************************************
     * Adds icons and information to the legend.
     * ******************************************************/
    function populateLegend(iconURLMap, defaultIconURL) {
        let tbody, tr, td;
        let colIdx = 0;
        let table = document.getElementById('legend-content');

        // Reset table content if necessary.
        if (table.tBodies.length === 0)
            tbody = table.createTBody();
        else
            tbody = table.tBodies[0];

        tbody.replaceChildren();

        tr = tbody.insertRow();

        for (let [stixType, iconURL] of iconURLMap)
        {
            let img = document.createElement('img');

            img.onerror = function() {
                // set the node's icon to the default if this image could not
                // load
                this.src = defaultIconURL;
                // our default svg is enormous... shrink it down!
                this.width = "37";
                this.height = "37";
            }
            img.src = iconURL;

            if (colIdx > 1)
            {
                colIdx = 0;
                tr = tbody.insertRow();
            }

            td = tr.insertCell();
            ++colIdx;

            td.append(img);
            td.append(stixType.charAt(0).toUpperCase() + stixType.substr(1).toLowerCase());
        }
    }

    /**
     * A JSON.stringify() replacer function to enable it to handle Map objects
     * like plain javascript objects.
     */
    function mapReplacer(key, value)
    {
        if (value instanceof Map)
        {
            let plainObj = {};
            for (let [subKey, subValue] of value)
                plainObj[subKey] = subValue;

            value = plainObj;
        }

        return value;
    }

    /**
     * Create a rendering of an array as part of rendering an overall STIX
     * object.
     *
     * @param arrayContent The array to render
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     * @param isRefs Whether the array is the value of a _refs property, i.e.
     *      an array of STIX IDs.  Used to produce a distinctive rendering for
     *      references.
     * @return The rendering as an array of DOM elements
     */
    function stixArrayContentToDOMNodes(
        arrayContent, edgeDataSet, stixIdToObject, isRefs=false
    )
    {
        let nodes = [];

        let ol = document.createElement("ol");
        ol.className = "selected-object-list";

        for (let elt of arrayContent)
        {
            let contentNodes;
            if (isRefs)
                contentNodes = stixStringContentToDOMNodes(
                    elt, edgeDataSet, stixIdToObject, /*isRef=*/true
                );
            else
                contentNodes = stixContentToDOMNodes(
                    elt, edgeDataSet, stixIdToObject
                );

            let li = document.createElement("li");
            li.append(...contentNodes);
            ol.append(li);
        }

        nodes.push(document.createTextNode("["));
        nodes.push(ol);
        nodes.push(document.createTextNode("]"));

        return nodes;
    }

    /**
     * Create a rendering of an object/dictionary as part of rendering an
     * overall STIX object.
     *
     * @param objectContent The object/dictionary to render, as a Map instance
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     * @param topLevel Whether objectContent is itself a whole STIX object,
     *      i.e. the top level of a content tree.  This is used to adjust the
     *      rendering, e.g. omit the surrounding braces at the top level.
     * @return The rendering as an array of DOM elements
     */
    function stixObjectContentToDOMNodes(
        objectContent, edgeDataSet, stixIdToObject, topLevel=false
    )
    {
        let nodes = [];

        if (!topLevel)
            nodes.push(document.createTextNode("{"));

        for (let [propName, propValue] of objectContent)
        {
            let propNameSpan = document.createElement("span");
            propNameSpan.className = "selected-object-prop-name";
            propNameSpan.append(propName + ":");

            let contentNodes;
            if (propName.endsWith("_ref"))
                 contentNodes = stixStringContentToDOMNodes(
                    propValue, edgeDataSet, stixIdToObject, /*isRef=*/true
                 );
            else if (propName.endsWith("_refs"))
                contentNodes = stixArrayContentToDOMNodes(
                    propValue, edgeDataSet, stixIdToObject, /*isRefs=*/true
                );
            else
                contentNodes = stixContentToDOMNodes(
                    propValue, edgeDataSet, stixIdToObject
                );

            let propDiv = document.createElement("div");
            propDiv.append(propNameSpan);
            propDiv.append(...contentNodes);

            if (!topLevel)
                propDiv.className = "selected-object-object-content";

            nodes.push(propDiv);
        }

        if (!topLevel)
            nodes.push(document.createTextNode("}"));

        return nodes;
    }

    /**
     * Create a rendering of a string value as part of rendering an overall
     * STIX object.
     *
     * @param stringContent The string to render
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     * @param isRef Whether the string is the value of a _ref property.  Used
     *      to produce a distinctive rendering for references.
     * @return The rendering as an array of DOM elements
     */
    function stixStringContentToDOMNodes(
        stringContent, edgeDataSet, stixIdToObject, isRef=false
    )
    {
        let nodes = [];

        let spanWrapper = document.createElement("span");
        spanWrapper.append(stringContent);

        if (isRef)
        {
            let referentObj = stixIdToObject.get(stringContent);
            if (referentObj)
            {
                spanWrapper.className = "selected-object-text-value-ref";
                spanWrapper.addEventListener(
                    "click", e => {
                        e.stopPropagation();
                        view.selectNode(referentObj.get("id"));
                        populateSelected(
                            referentObj, edgeDataSet, stixIdToObject
                        );
                    }
                );
            }
            else
                spanWrapper.className = "selected-object-text-value-ref-dangling";
        }
        else
            spanWrapper.className = "selected-object-text-value";

        nodes.push(spanWrapper);

        return nodes;
    }

    /**
     * Create a rendering of a value for which no other special rendering
     * applies, as part of rendering an overall STIX object.
     *
     * @param otherContent The content to render
     * @return The rendering as an array of DOM elements
     */
    function stixOtherContentToDOMNodes(otherContent)
    {
        let nodes = [];

        let asText;
        if (otherContent === null)
            asText = "null";
        else if (otherContent === undefined)
            asText = "undefined";  // also just in case??
        else
            asText = otherContent.toString();

        let spanWrapper = document.createElement("span");
        spanWrapper.append(asText);
        spanWrapper.className = "selected-object-nontext-value";
        nodes.push(spanWrapper);

        return nodes;
    }

    /**
     * Create a rendering of a value, as part of rendering an overall STIX
     * object.  This function dispatches to one of the more specialized
     * rendering functions based on the type of the value.
     *
     * @param stixContent The content to render
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     * @return The rendering as an array of DOM elements
     */
    function stixContentToDOMNodes(stixContent, edgeDataSet, stixIdToObject)
    {
        let nodes;

        if (stixContent instanceof Map)
            nodes = stixObjectContentToDOMNodes(
                stixContent, edgeDataSet, stixIdToObject
            );
        else if (Array.isArray(stixContent))
            nodes = stixArrayContentToDOMNodes(
                stixContent, edgeDataSet, stixIdToObject
            );
        else if (
            typeof stixContent === "string" || stixContent instanceof String
        )
            nodes = stixStringContentToDOMNodes(
                stixContent, edgeDataSet, stixIdToObject
            );
        else
            nodes = stixOtherContentToDOMNodes(stixContent);

        return nodes;
    }

    /**
     * Populate the Linked Nodes box with the connections of the given STIX
     * object.
     *
     * @param stixObject The STIX object to display connection information
     *      about
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     */
    function populateConnections(stixObject, edgeDataSet, stixIdToObject)
    {
        let objId = stixObject.get("id");

        let edges = edgeDataSet.get({
            filter: item => (item.from === objId || item.to === objId)
        });

        let eltConnIncoming = document.getElementById("connections-incoming");
        let eltConnOutgoing = document.getElementById("connections-outgoing");

        eltConnIncoming.replaceChildren();
        eltConnOutgoing.replaceChildren();

        let listIn = document.createElement("ol");
        let listOut = document.createElement("ol");

        eltConnIncoming.append(listIn);
        eltConnOutgoing.append(listOut);

        for (let edge of edges)
        {
            let targetList;
            let summaryNode = document.createElement("summary");
            let otherEndSpan = document.createElement("span");
            let otherEndObj;

            if (objId === edge.from)
            {
                otherEndObj = stixIdToObject.get(edge.to);
                otherEndSpan.append(otherEndObj.get("type"));

                summaryNode.append(edge.label + " ");
                summaryNode.append(otherEndSpan);

                targetList = listOut;
            }
            else
            {
                otherEndObj = stixIdToObject.get(edge.from);
                otherEndSpan.append(otherEndObj.get("type"));

                summaryNode.append(otherEndSpan);
                summaryNode.append(" " + edge.label);

                targetList = listIn;
            }

            otherEndSpan.className = "selected-object-text-value-ref";
            otherEndSpan.addEventListener(
                "click", e => {
                    view.selectNode(otherEndObj.get("id"));
                    populateSelected(otherEndObj, edgeDataSet, stixIdToObject);
                }
            );

            let li = document.createElement("li");
            let detailsNode = document.createElement("details");

            targetList.append(li);
            li.append(detailsNode);
            detailsNode.append(summaryNode);

            let objRenderNodes = stixObjectContentToDOMNodes(
                otherEndObj, edgeDataSet, stixIdToObject, /*topLevel=*/true
            );
            detailsNode.append(...objRenderNodes);
        }
    }

    /**
     * Populate relevant webpage areas according to a particular STIX object.
     *
     * @param stixObject The STIX object to display information about
     * @param edgeDataSet A visjs DataSet instance with graph edge data derived
     *      from STIX content
     * @param stixIdToObject A Map instance mapping STIX IDs to STIX objects as
     *      Maps, containing STIX content.
     */
    function populateSelected(stixObject, edgeDataSet, stixIdToObject) {
        // Remove old values from HTML
        let selectedContainer = document.getElementById('selection');
        selectedContainer.replaceChildren();

        let contentNodes = stixObjectContentToDOMNodes(
            stixObject, edgeDataSet, stixIdToObject, /*topLevel=*/true
        );
        selectedContainer.append(...contentNodes);

        populateConnections(stixObject, edgeDataSet, stixIdToObject);
    }

    function selectedNodeClick() {
      let selected = document.getElementById('selected');
      if (selected.className.indexOf('clicked') === -1) {
        selected.className += " clicked";
        selected.style.position = 'absolute';
        selected.style.left = '25px';
        selected.style.width = (window.innerWidth - 110) + "px";
        selected.style.top = (document.getElementById('canvas').offsetHeight + 25) + "px";
        selected.scrollIntoView(true);
      } else {
        selected.className = "sidebar"
        selected.removeAttribute("style")
      }
    }

    /* ******************************************************
     * When the page is ready, setup the visualization and bind events
     * ******************************************************/
    document.getElementById('selected').addEventListener('click', selectedNodeClick, false);
    document.getElementById("legend").addEventListener("click", legendClickHandler, {capture: true});

    // We leverage require() to get this variable
    vizStixWrapper(latest_json_file_contents.data);
});
