/*********************************************************************
*                           Label Tamer                              *
**********************************************************************
   A Google Apps Script and spreadsheet that assists in taming
   out-of-control Gmail labels.
**********************************************************************
*                      LICENSING AND DISCLAIMER                      *
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
*                            INSTRUCTIONS                            *
**********************************************************************
   1. Make a copy of the spreadsheet associated with
      this programming, which can be found at:
        https://docs.google.com/spreadsheet/ccc?key=0AsDqHqrjcsSMdHh0WVJXWkRfVjhOX3FBT19uRnpIUUE&usp=sharing
   2. Open 'Tools' > 'Script editor...' and run the 
      'AddAllLabelsToSheet' function. Accept the permissions.							
   3. For each label in Column A select an action in Column B.
      Options for Column B are:
        Keep   - keep the label
        Delete - delete the label
        Rename - rename the label
        Move   - move all messages in this label to a
                 different label 
      If you select 'Move' or 'Rename', add a label name in
      column C.							
   4. In the 'Script editor...' run the 
      'ProcessLabelsFromSheet' function. Accept the permissions.							
   5. While iterating through the labels, Column B will be
      updated with a current status. If processing a large
      number of labels, this function may time out after five
      minutes. Re-run the function and it will pick up where
      it left off.				                              
*********************************************************************/

function AddAllLabelsToSheet() {
  var labels = GmailApp.getUserLabels();
  var sheet = SpreadsheetApp.getActiveSheet();
  
  for(var row_i = 0; row_i < labels.length; ++row_i) {
    sheet.appendRow([labels[row_i].getName(), '', '']);
  }
}

function ProcessLabelsFromSheet() {
  var sheet = SpreadsheetApp.getActiveSheet();
  var rows = sheet.getDataRange();
  var values = rows.getValues();
  
  for(var row_i = 8; row_i < rows.getNumRows(); ++row_i) {
    var row = values[row_i];
    if(row[1].toLowerCase() == 'delete') {
      Logger.log('Deleting ' + row[0]);
      
      try {
        var label = GmailApp.getUserLabelByName(row[0]);
        label.deleteLabel();
        var cell = rows.getCell(row_i + 1, 2);
        cell.setValue(['deleted']);
      } catch(err) {
        Logger.log("Label doesn't exist.");
        var cell = rows.getCell(row_i + 1, 2);
        cell.setValue(['deleted']);
      }      
    } else if(row[1].toLowerCase() == 'move') {
      Logger.log('Moving messages in label ' + row[0] + ' to label ' + row[2]);
      
      try {
        var old_label = GmailApp.getUserLabelByName(row[0]);
        var new_label = GmailApp.getUserLabelByName(row[2]);
        var threads = old_label.getThreads();
        for(thread_i = 0; thread_i < threads.length; ++thread_i) {
          var thread = threads[thread_i];
         thread.addLabel(new_label);
         thread.removeLabel(old_label);
        }
      
        if(old_label.getThreads() == 0) {
          old_label.deleteLabel();
          var cell = rows.getCell(row_i + 1, 2);
          cell.setValue(['moved to']);
        }
      } catch(err) {
        Logger.log("One of the labels doesn't exist.");
        var cell = rows.getCell(row_i + 1, 2);
        cell.setValue(['moved to']);
      }
    } else if(row[1].toLowerCase() == 'rename') {
      Logger.log('Renaming label ' + row[0] + ' to ' + row[2] + '.');
      
      try {
        var old_label = GmailApp.getUserLabelByName(row[0]);
        var new_label = GmailApp.createLabel(row[2]);
        
        var more_threads = true;
        while(more_threads) {
          var threads = old_label.getThreads(0, 100);
          
          if(threads.length == 0) {
            more_threads = false;
          }

          new_label.addToThreads(threads);
          old_label.removeFromThreads(threads);
        }
        
        old_label.deleteLabel();
        
        var cell = rows.getCell(row_i + 1, 2);
        cell.setValue(['renamed to']);
      } catch(err) {
        Logger.log("One of the labels doesn't exist.");
      }
    }
  }
}
