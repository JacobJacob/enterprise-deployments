//**********************************************************************
//*                      LICENSING AND DISCLAIMER                      *
//**********************************************************************
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
//   DISCLAIMER:
//
//   (i) GOOGLE INC. ("GOOGLE") PROVIDES YOU ALL CODE HEREIN "AS IS"
//   WITHOUT ANY WARRANTIES OF ANY KIND, EXPRESS, IMPLIED, STATUTORY OR
//   OTHERWISE, INCLUDING, WITHOUT LIMITATION, ANY IMPLIED WARRANTY OF
//   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-
//   INFRINGEMENT; AND
//
//   (ii) IN NO EVENT WILL GOOGLE BE LIABLE FOR ANY LOST REVENUES,
//   PROFIT OR DATA, OR ANY DIRECT, INDIRECT, SPECIAL, CONSEQUENTIAL,
//   INCIDENTAL OR PUNITIVE DAMAGES, HOWEVER CAUSED AND REGARDLESS OF
//   THE THEORY OF LIABILITY, EVEN IF GOOGLE HAS BEEN ADVISED OF THE
//   POSSIBILITY OF SUCH DAMAGES, ARISING OUT OF THE USE OR INABILITY
//   TO USE, MODIFICATION OR DISTRIBUTION OF THIS CODE OR ITS
//   DERIVATIVES.
//**********************************************************************
//
// This script is a reference implementation of a function to delete all
// child Sites pages from a given root page.
//

function deleteChildPages() {
  
  // Root page Sites URL for all deletable pages
  var archive_page_root_url = "https://sites.google.com/a/example.com/sample/home/archive";
  
  // Load the root page in order to request all of its children pages
  var page = SitesApp.getPageByUrl(archive_page_root_url);
  
  // Retrieve all child pages
  var child_pages = page.getChildren();
  
  // Retrieve and delete all child pages
  for (var p in child_pages) {

    Logger.log("Deleting page: [" + child_pages[p].getName() + "]");

    // To actually delete the pages after testing, uncomment this line:
    //child_pages[p].deletePage();      

  }
}
