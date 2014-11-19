/*********************************************************************
*                      Parent Label Checker                          *
**********************************************************************
   A Google Apps Script to ensure that all sub-labels have
   parent labels. If the parent label is a Gmail system label, it
   precedes the parent label with an underscore (_) to avoid conflict.
**********************************************************************
*                    LICENSING AND DISCLAIMER                        *
**********************************************************************
   Copyright 2014 Google Inc. All Rights Reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   DISCLAIMER:

   (i) GOOGLE INC. ("GOOGLE") PROVIDES YOU ALL CODE HEREIN "AS IS"
   WITHOUT ANY WARRANTIES OF ANY KIND, EXPRESS, IMPLIED, STATUTORY OR
   OTHERWISE, INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTY OF
   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-
   INFRINGEMENT; AND

   (ii) IN NO EVENT WILL GOOGLE BE LIABLE FOR ANY LOST REVENUES,
   PROFIT OR DATA, OR ANY DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
   INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF
   THE THEORY OF LIABILITY, EVEN IF GOOGLE HAS BEEN ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGES, ARISING OUT OF THE USE OR INABILITY
   TO USE, MODIFICATION OR DISTRIBUTION OF THIS CODE OR ITS
   DERIVATIVES.
**********************************************************************
*                              NOTES                                 *
**********************************************************************
This script takes system labels into consideration by renaming any
labels which would become a system label, prepending an underscore (_)
to the system label portion of the name.

Additionally, if there are a large number of labels to process, this
script may time out and display the message:
     "Exceeded maximum execution time (Dismiss)"
in a red box. Not to worry! In order to allow the processing to be\
persistent, this script automatically adds a trigger to launch again
(and pick up where it left off) every ten minutes. When processing
completes, the trigger is removed.
*********************************************************************/

/* We create an array operator, has, which checks to see if an item is
   a member of the array. */
Array.prototype.has = function(obj) {
  var i = this.length;
  while (i--) {
    if (this[i] == obj) {
      return true;
    }
  }  
  return false;
}


/* We create an array operator, reduce, which returns a new array
   containing only items that don't matching a string. */
Array.prototype.reduce = function(string) {
  var result = new Array();
  for(var i = 0; i < this.length; i++) {
    if(this[i].indexOf(string) == -1) {
      result.push(this[i]);
    }
  }
  return result;
}


/* We create an array operator, keep, which returns a new array
   containing only items that do match a string. */
Array.prototype.keep = function(string) {
  var result = new Array();
  for(var i = 0; i < this.length; i++) {
    if(this[i].indexOf(string) != -1) {
      result.push(this[i]);
    }
  }
  
  return result;
}


// A helper function for mapping.
function _getName(obj) {
  return obj.getName();
}


// The primary function of this script. Run this one!
function ParentLabelChecker() {
  /* Remove any automatic triggers for this function. We
     don't want there to be more than one. */
  var triggers = ScriptApp.getProjectTriggers();
  for(var i = 0; i < triggers.length; i++) {
    ScriptApp.deleteTrigger(triggers[i]);
  }

  /* Add an automatic trigger to relaunch this app every ten
     minutes. This is necessary because there are some
     cirumstances in which this script will take longer than
     five minutes to run, and AppsScript scripts have a five-
     minute execution time-out. In order to prevent this
     script from continually executing when it's no longer
     needed, the last thing it will do once it terminates
     properly is remove this trigger. */
  var everyTenMinutes2 = ScriptApp.newTrigger('_ParentLabelChecker')
      .timeBased().everyMinutes(10).create();

  // Why wait ten minutes to auto-launch this function?
  _ParentLabelChecker();
}


// A helper that contains the nuts and bolts of this application.
function _ParentLabelChecker() {
  /* Get an array containing all existing label names excepting
     any labels in our todo list. */
  var labels = GmailApp.getUserLabels().map(_getName)
      .reduce('zzz_PLC_TODO_/');

  // For each label...  
  var i = labels.length;
  while(i--) {
    var label = labels[i];
    Logger.log('Processing label: ' + label);

    // Break the label up into its nested parts.
    var label_parts = label.split('/');

    /* Let's start with the assumption that the parent label isn't
       a system label. */
    var system_label = false;
    
    // For each nested part of the label...    
    for(var j = 1; j < label_parts.length; j++) {
      // Identify what the parent label would be.
      parent_label = label_parts.slice(0, j).join('/');

      if(system_label) {
         /* If we know it's buried under a system label, make note
            of it for later. */
        GmailApp.createLabel('zzz_PLC_TODO_/' + parent_label);
        Logger.log('Special case for ' + parent_label);
      } else {      
        /* We don't know if it's a system label, so let's check if
           the parent exists. */
        if(! labels.has(parent_label)) {
          // The parent does not exist. Let's create it!
          GmailApp.createLabel(parent_label);

          /* Now we need to see if the label was created, because
             createLabel won't fail if it's already a system label. */
         try {
            // Is it a user label?
            GmailApp.getUserLabelByName(parent_label).getName();
            // Yup. Let's take note!
            Logger.log('Label created: '+ parent_label);
          } catch(err) {
            // Whoa. Nope. Doesn't exist. Must be a system label.
            Logger.log('Could not create ' + parent_label);
            Logger.log('Special case for ' + label);

            system_label = true; 

            // Make note of the label for later processing.            
            GmailApp.createLabel('zzz_PLC_TODO_');
            GmailApp.createLabel('zzz_PLC_TODO_/' + parent_label);
            GmailApp.createLabel('zzz_PLC_TODO_/' + label);
          }
        }
      }
    }
  }

  /* These labels are all nested under a label with the same name
     as a system label, so we need to do something special with
     them. */
  var todo_labels = GmailApp.getUserLabels().map(_getName)
      .keep('zzz_PLC_TODO_/');
  for(var i = 0; i < todo_labels.length; i++) {
    // The todo label contains the name of the original label.
    var label_parts = todo_labels[i].split('/');
    var label_name = label_parts.slice(1).join('/');
    
    /* Believe it or not, the API doesn't have the ability to rename
       labels, so instead we need to iterate through the threads of
       the original label and add the new label to them. Then we can
       remove the original label. */
    var old_label = GmailApp.getUserLabelByName(label_name);
    var new_label = GmailApp.createLabel('_' + label_name);
    // If your goal is to simply remove the label from the system label,
    // comment out the above line and remove the comments for the
    // following:
    //var new_label = GmailApp.createLabel(label_name.split('/').slice(1).join('/'));

    Logger.log('Moving threads from ' + label_name + ' to _' + label_name);
    
    // Keep iterating through the thread for all available threads.
    var more_threads = true;
    while(more_threads) {
      // The old label might be a system label name, which would fail.
      try {
        /* We can grab threads in blocks of 100 but I'm sticking with 50
           to play it safe. Each time we iterate, we'll be requesting the
           currently first 50 labels. To do so, the index always starts at
           0. */
        threads = old_label.getThreads(0, 50);
        
        // Are there more threads?
        if(threads.length == 0) {
          // No more threads! Let's close out this todo label.
          old_label.deleteLabel();
          GmailApp.getUserLabelByName(todo_labels[i]).deleteLabel();
          more_threads = false;
        } else {
          // Yup, we have threads here! Let's swap labels!
          new_label.addToThreads(threads);
          old_label.removeFromThreads(threads);
        }
      } catch(err) {
        // Yes, it was a system label. Let's remove it from our list.
        Logger.log('===== getThreads error: ' + err);
        try {
          GmailApp.getUserLabelByName(todo_labels[i]).deleteLabel();
        } catch(err) {
          Logger.log('===== deleteLabel error: ' + err);
          more_threads = false;
        }
        more_threads = false;
      }
    }
    
  }
  // We have nothing more to process, remove the todo label.
  GmailApp.getUserLabelByName('zzz_PLC_TODO_').deleteLabel();

  // We've made it through all labels. Clean up our trigger!  
  var triggers = ScriptApp.getProjectTriggers();
  for(var i = 0; i < triggers.length; i++) {
    ScriptApp.deleteTrigger(triggers[i]);
  }
}